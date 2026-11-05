# Native build recipe reference

These are retained native command bodies from the approved R3 source
`3c48d7e7e9d5c682d2e3056070be24b97669f2e5`, not a CI configuration or a
new release runner. See [Local builds](local-build.md) for usable local entrypoints.

The original order, per-job environment, matrix and action inputs still matter.
`git show <R3>:<original-path>` retrieves those exact historical inputs locally;
the SHA-256 below binds each original file. No GitHub workflow is installed.

Code blocks here are **historical reference**, not commands to run wholesale.
Runner expressions (`${{ ... }}`), runner paths and credentials must be replaced
with explicit local inputs. Cache deletion, toolchain uninstallation, uploads,
secret provisioning, tagging and deployment steps are not local build defaults.
**Do not paste or execute these blocks as a local build plan.** They include
retired publishing, signing, privileged setup and runner/cache cleanup operations,
not just compilation. The current policy is unsigned Windows/Linux local output,
with macOS signing only. No archived command overrides that decision. No command
in this document has been newly executed or validated by the CI removal.

Original repository URLs and asset/manifests in these bodies are historical;
the current verified Windows vendor releases are at `gjovanov/roomler-ai`. Their
patch-to-build mapping must be reviewed, not inferred from these old recipes.

For an existing vendor binary, retain the exact recipe from its actual build
revision in its source offer; a rewritten recipe cannot establish its provenance.



## release-agent

Original path: `.github/workflows/release-agent.yml`; SHA-256: `9eb134f46cbfc3332bb0f00fc304005adeeaa7839aea21502a6b8651c24b14aa`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve version + tag (original line 141)

```text
set -euo pipefail
# Grep the [workspace.package] table for the declared version.
cargo_version=$(awk '
  /^\[workspace\.package\]/ {in_section=1; next}
  /^\[/ {in_section=0}
  in_section && /^version[[:space:]]*=/ {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)
echo "Cargo.toml workspace version: ${cargo_version}"

if [[ "$GITHUB_EVENT_NAME" == "schedule" ]]; then
  # Weekly cache-seed rehearsal: no tag, no inputs. Build whatever
  # master currently is, artifacts-only — the run exists for its
  # master-ref Swatinem saves, which every tag build restores.
  version="${cargo_version}"
  tag="agent-v${version}"
  is_release=false
elif [[ "$GITHUB_EVENT_NAME" == "push" ]]; then
  tag="${GITHUB_REF_NAME}"
  version="${tag#agent-v}"
  is_release=true
else
  version="${INPUT_VERSION:-}"
  # Shape-check before the value is used anywhere else. A dispatch
  # input is attacker-influenced in the insider case above, and the
  # mismatch check further down compares it to Cargo.toml — which
  # is a correctness gate, not a syntax one.
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "::error::Invalid version input: '${version}' (expected N.N.N or N.N.N-rc.N)"
    exit 1
  fi
  tag="agent-v${version}"
  if [[ "${INPUT_PUBLISH_RELEASE:-}" == "true" ]]; then
    is_release=true
  else
    is_release=false
  fi
fi

echo "Resolved: version=${version} tag=${tag} is_release=${is_release}"

if [[ "${cargo_version}" != "${version}" ]]; then
  echo "::error::Version mismatch: requested ${version} but Cargo.toml has ${cargo_version}"
  exit 1
fi

# Derive the MSI ProductVersion. Windows Installer IGNORES the
# 4th (revision) version field for upgrade comparison, so the
# raw semver `0.3.0-rc.N` — which cargo-wix maps to `0.3.0.N` —
# made every rc look like the same `0.3.0` product: WiX
# MajorUpgrade never saw a "newer" version, never removed the
# prior one, and rc builds piled up (8 perMachine versions
# found coexisting on a host 2026-06-01). Fix: put the rc in
# the 3rd (build) field so MSI ProductVersions are monotonic —
# `MAJOR.MINOR.RC`. A final (non-rc) release maps the build
# field to 65535 so it outranks every rc of that minor. Only
# the MSI-internal ProductVersion changes; the .msi *filename*
# keeps the readable semver (see the rename steps below).
# Assumes the project's `MAJOR.MINOR.0-rc.N` scheme (patch == 0
# for rc builds) — fails loudly otherwise so the mapping can't
# silently collide.
#
# ⚠️ THIS MAPPING HAS FIVE MORE COPIES:
# agents/meshharbord/src/artifact_version.rs::msi_product_version_for
# (download verification),
# agents/meshharbord/src/version_sweep.rs::own_msi_version
# (coexisting-MSI sweep — a divergence there makes an agent rank
# its OWN install as older and uninstall itself), and the three
# build.rs VERSIONINFO embeds (meshharbord, meshharbor-cli-shim,
# meshharbor-cli — `file_version`): those stamp the EXE
# FILEVERSION shown by Explorer/EDR inventory; a divergence there
# is cosmetic-but-confusing (EXE claims a different version than
# the MSI), nothing asserts it at build time.
# The self-updater reads the ProductVersion back out of the
# downloaded MSI and refuses to install one that does not carry
# the version the release manifest claimed — that is what stops a
# tampered manifest from pointing a high version number at a
# genuinely-signed OLDER build. The two copies MUST change
# together: if they diverge, every agent refuses every update and
# the symptom is a silent fleet-wide update freeze, not an error.
# `cargo test -p meshharbord --lib -- --ignored real_published_msi`
# re-checks the Rust side against a real published MSI.
if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$ ]]; then
  vmajor="${BASH_REMATCH[1]}"; vminor="${BASH_REMATCH[2]}"
  vpatch="${BASH_REMATCH[3]}"; vrc="${BASH_REMATCH[4]}"
  if [[ "$vpatch" != "0" ]]; then
    echo "::error::rc builds must have patch == 0 (got ${version}); the MAJOR.MINOR.RC MSI mapping would collide with a patched rc"
    exit 1
  fi
  if (( vrc > 65535 )); then
    echo "::error::rc number ${vrc} exceeds the MSI build-field max (65535)"
    exit 1
  fi
  msi_version="${vmajor}.${vminor}.${vrc}"
elif [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  # Finals — two eras, split at 0.4 (the rc train ended with
  # 0.3.0-rc.*):
  #  * 0.4+ ships plain MAJOR.MINOR.PATCH releases, so PATCH is
  #    the build field (0.4.5 → 0.4.5): monotonic within the
  #    minor, no two 0.4.x MSIs share a ProductVersion.
  #  * pre-0.4 keeps the legacy 65535 rule so historical answers
  #    never change.
  # Mirrored in msi_product_version_for AND version_sweep's
  # own_msi_version — all three MUST agree (see the warning above).
  fmajor="${BASH_REMATCH[1]}"; fminor="${BASH_REMATCH[2]}"; fpatch="${BASH_REMATCH[3]}"
  if (( fmajor > 0 || fminor >= 4 )); then
    if (( fpatch > 65535 )); then
      echo "::error::patch ${fpatch} exceeds the MSI build-field max (65535)"
      exit 1
    fi
    msi_version="${fmajor}.${fminor}.${fpatch}"
  else
    msi_version="${fmajor}.${fminor}.65535"
  fi
else
  echo "::error::cannot derive an MSI version from '${version}' (expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N)"
  exit 1
fi
echo "Resolved MSI ProductVersion: ${msi_version} (from ${version})"

echo "version=${version}" >> "$GITHUB_OUTPUT"
echo "msi_version=${msi_version}" >> "$GITHUB_OUTPUT"
echo "tag=${tag}"         >> "$GITHUB_OUTPUT"
echo "is_release=${is_release}" >> "$GITHUB_OUTPUT"
```


### Archived step: Configure apt retries and refresh the index (original line 304)

```text
echo 'Acquire::Retries "3";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries
sudo apt-get update -qq
```


### Archived step: Verify the build deps really landed (fallback to apt-get) (original line 328)

```text
set -euo pipefail
pkgs="libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev cmake libclang-dev pkg-config libvpx-dev libasound2-dev libglib2.0-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev patchelf"
check() {
  sudo ldconfig
  for m in vpx xcb xcb-shm xcb-randr alsa glib-2.0 gtk+-3.0 libsoup-3.0 javascriptcoregtk-4.1 webkit2gtk-4.1 ayatana-appindicator3-0.1; do
    pkg-config --exists "$m" || { echo "missing: pkg-config module $m"; return 1; }
  done
  for t in cmake patchelf; do
    command -v "$t" >/dev/null || { echo "missing: $t"; return 1; }
  done
  # Not `grep -q`: it exits at the first match, ldconfig takes SIGPIPE,
  # and under pipefail a present library would read as missing.
  ldconfig -p | grep 'libvpx\.so' >/dev/null || { echo "missing: libvpx.so in the loader cache"; return 1; }
  compgen -G '/usr/lib/llvm-*/lib/libclang*.so*' >/dev/null || { echo "missing: libclang"; return 1; }
}
if ! check; then
  echo "::warning::the cached apt set did not deliver the release build deps; installing directly"
  sudo apt-get update -qq
  # shellcheck disable=SC2086
  sudo apt-get install -y $pkgs
fi
check || { echo "::error::release build deps still missing after the fallback install"; exit 1; }
```


### Archived step: Install cargo-deb (original line 380)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
```


### Archived step: Fetch vendored FFmpeg 9.0.1 (for the ffmpeg-encoder HEVC backend) (original line 385)

```text
set -euo pipefail
# Prebuilt LGPL FFmpeg 9.0.1 (nvenc/qsv/amf/vaapi/vulkan HEVC + the
# LGPL libkvazaar SW encoder; NO GPL libx265 → the MIT agent stays
# license-clean, matching the Windows vcpkg policy). Published once
# at the `vendored-ffmpeg-9.0.1` release and reused by every build
# instead of compiling FFmpeg from source: Ubuntu apt ships only
# FFmpeg 6.1, but `ffmpeg-next = 9.0` needs 9.x.
gh release download vendored-ffmpeg-9.0.1 \
  --repo "${{ github.repository }}" \
  --pattern 'ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz' \
  --dir /tmp/ffdl
# P3e lever B (Linux twin): the MINIMAL from-source build — the ten
# HW encoders + their parsers, nothing else (whole lib dir 2.5 MB
# vs ~50 MB of libav* in the old BtbN re-upload; the agent's
# cascade is locked to nvenc/qsv/amf by a unit test, so kvazaar/
# vaapi/every-decoder were unreachable). Vendor job's runtime probe
# asserts the encoder set; rollback = drop the `-minimal` suffix.
# FR-77 P4 added `-vaapi`: `--enable-vaapi` + the four `*_vaapi`
# encoders, with libva/libva-drm/libdrm BUILT INTO the tree (the
# bundler below carries them; no `Depends` on the system's libva,
# which the offline `dpkg --install` fallback could not satisfy
# without leaving a daemon that fails to load). Rollback = drop
# that suffix. FR-78 P0 added `-vulkan` (three Vulkan encoders,
# dlopen'd — no new DT_NEEDED); rollback = drop that one. FR-85 P4c
# added `-h264dec-aac` (the software h264 decoder the recorder's
# editor needs and the aac encoder for its sound, inside libavcodec,
# no new DT_NEEDED); rollback = drop that one.
sudo mkdir -p /opt/meshharbor-ffmpeg
sudo tar xf /tmp/ffdl/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz \
  -C /opt/meshharbor-ffmpeg --strip-components=1
# BtbN's pkgconfig files hardcode the build-machine prefix; rewrite
# it to our extract path so pkg-config emits correct -L/-I flags.
sudo sed -i "s|^prefix=.*|prefix=/opt/meshharbor-ffmpeg|" \
  /opt/meshharbor-ffmpeg/lib/pkgconfig/*.pc
{
  echo "FFMPEG_DIR=/opt/meshharbor-ffmpeg"
  echo "PKG_CONFIG_PATH=/opt/meshharbor-ffmpeg/lib/pkgconfig"
  echo "LD_LIBRARY_PATH=/opt/meshharbor-ffmpeg/lib"
} >> "$GITHUB_ENV"
# ── FR-62 A2 drift gate: the vendored libs must have been built from
#    the FFmpeg source patches committed in this checkout. The vendor
#    build wrote MESHHARBOR-PATCHES.txt (sha256 per patch) into the
#    tarball; assert it equals the committed set. A mismatch or an
#    absent manifest while patches exist means the vendored asset is
#    STALE — re-run vendor-ffmpeg-windows.yml (Linux + Windows jobs)
#    before tagging. Fail closed: never ship an agent whose FFmpeg
#    lacks the source patches the code assumes.
shopt -s nullglob
committed=( "$GITHUB_WORKSPACE"/.github/ffmpeg-patches/*.patch )
if [ ${#committed[@]} -gt 0 ]; then
  # Normalise both sides to `<sha256-lowercase> <basename>` (one
  # space), sorted — robust to the manifest's two-space sha256sum
  # format and to the absolute paths in `committed`. (A greedy
  # `sed 's#.*/##'` on the sha256sum output would strip the HASH too,
  # since `.` matches the spaces before the path — the bug this
  # replaces.)
  want=$(for f in "${committed[@]}"; do printf '%s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f")"; done | sort)
  got_file=/opt/meshharbor-ffmpeg/MESHHARBOR-PATCHES.txt
  if [ ! -f "$got_file" ]; then
    echo "::error::vendored FFmpeg carries no MESHHARBOR-PATCHES.txt but ${#committed[@]} patch(es) are committed — re-vendor before tagging (see .github/ffmpeg-patches/)"; exit 1
  fi
  got=$(awk 'NF{print tolower($1), $NF}' "$got_file" | sort)
  if [ "$want" != "$got" ]; then
    echo "::error::vendored FFmpeg patch manifest != committed .github/ffmpeg-patches/ — re-run vendor-ffmpeg-windows.yml"
    echo "--- committed ---"; echo "$want"; echo "--- in asset ---"; echo "$got"; exit 1
  fi
  echo "FR-62 A2 gate OK: vendored FFmpeg built from ${#committed[@]} committed patch(es)"
fi
```


### Archived step: FR-24 gate — the LGPL source offer covers what this release ships (original line 458)

```text
set -euo pipefail
# ── THIRD-PARTY-NOTICES.md's written offer points at the
#    corresponding-source bundle on vendored-ffmpeg-9.0.1. That bundle
#    must carry every change our builds make to FFmpeg: the committed
#    .github/ffmpeg-patches/ AND the vcpkg port at the recipe's
#    $baseline. lgpl-source-offer.yml publishes what it was built from
#    as `…corresponding-source.inputs.txt` (`<hash> <name>` per patch,
#    `<sha> vcpkg-baseline`, and the sha256 of each recipe file it
#    ships); compare it with this checkout. The recipe counts since
#    FR-85 P4c: the configure options live there, not in a patch, so
#    a build whose options changed passed this gate against an offer
#    that described the old ones.
#    ⚠️ From #1249 (2026-09-02) to 2026-09-24 every release shipped a
#    patched FFmpeg while the offered source omitted the patch and
#    said "we apply no patches", and nothing checked. Fail closed:
#    an offer claiming completeness it lacks is a compliance claim we
#    cannot make. Bump the two `9.0.1` names below with the download
#    step above when FFmpeg moves.
shopt -s nullglob
committed=( "$GITHUB_WORKSPACE"/.github/ffmpeg-patches/*.patch )
baseline=$(sed -n "s/^[[:space:]]*\$baseline = '\([0-9a-f]\{40\}\)'.*/\1/p" \
  "$GITHUB_WORKSPACE/.github/workflows/vendor-ffmpeg-windows.yml" | head -1)
if [ -z "$baseline" ]; then
  echo "::error::no \$baseline in vendor-ffmpeg-windows.yml — re-derive this gate's parse"; exit 1
fi
want=$( { for f in "${committed[@]}"; do printf '%s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f")"; done
          printf '%s %s\n' "$baseline" vcpkg-baseline
          for r in vendor-ffmpeg-windows.yml vendor-ffmpeg-macos.yml; do
            printf '%s %s\n' "$(sha256sum "$GITHUB_WORKSPACE/.github/workflows/$r" | cut -d' ' -f1)" "recipe/$r"
          done; } | sort )
mkdir -p /tmp/offer
if ! gh release download vendored-ffmpeg-9.0.1 --repo "${{ github.repository }}" \
     --pattern 'ffmpeg-n9.0.1-corresponding-source.inputs.txt' --dir /tmp/offer --clobber; then
  echo "::error::the LGPL offer on vendored-ffmpeg-9.0.1 publishes no inputs.txt — dispatch lgpl-source-offer.yml before tagging"; exit 1
fi
got=$(awk 'NF{print tolower($1), $NF}' /tmp/offer/ffmpeg-n9.0.1-corresponding-source.inputs.txt | sort)
if [ "$want" != "$got" ]; then
  echo "::error::the published LGPL corresponding source was not built from this checkout's FFmpeg patches, vcpkg baseline and build recipe — dispatch lgpl-source-offer.yml before tagging"
  echo "--- this checkout ---"; echo "$want"; echo "--- in the offer ---"; echo "$got"; exit 1
fi
echo "FR-24 gate OK: the LGPL offer carries ${#committed[@]} patch(es) + vcpkg baseline ${baseline:0:8} + this checkout's recipe"
```


### Archived step: Build agent (release, full + vp9-444 + vp9-444-bindgen) (original line 530)

```text
cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ffmpeg-encoder,ssh-server,viewer-indicator-x11"
```


### Archived step: Build the meshharbor CLI shim (shipped in the .deb alongside meshharbord) (original line 542)

```text
cargo build -p meshharbor-cli-shim --release
test -f target/release/meshharbor-shim || { echo "::error::meshharbor-shim not produced — the cargo-deb assets entry would fail"; exit 1; }
```


### Archived step: Bundle FFmpeg into the .deb (self-contained, RPATH) (original line 547)

```text
set -euo pipefail
# Ubuntu 24.04 ships FFmpeg 6.1 (libavcodec.so.60) but the agent links
# 9.0.1 (libavcodec.so.63), so the .deb must CARRY its own FFmpeg or it
# won't start on a stock box. Ship each lib under its SONAME as a real
# file (no symlinks) into /usr/lib/meshharbor-agent; RPATH wires it up.
# patchelf comes from the cached apt set at the top of this job.
dst=agents/meshharbord/vendor-ffmpeg
rm -rf "$dst" && mkdir -p "$dst"
# P3e Phase 3: bundle ONLY the vendored libs the binary actually
# references. Before the ffmpeg codec+format trim the binary linked
# all seven libav* and the blanket copy was accurate; post-trim it
# links avcodec/avformat/avutil/swresample only, and blindly copying
# the rest (avfilter alone is ~18 MB of .so) kept the .deb at
# ~56 MiB for dead weight. `ldd` lists the TRANSITIVE closure, so
# deriving the keep-set from it stays correct if linkage changes
# again — a lib that stops being referenced silently drops out, and
# one that starts being referenced is caught by the empty-copy guard
# + the stock-24.04 load check below.
# Pass 1: the binary's own DT_NEEDED (ldd prints the SONAME in $1
# even for not-yet-findable libs). Passes 2..n: each copied lib's
# OWN needs — ldd cannot traverse INTO a lib it can't find, so
# vendored-lib -> vendored-lib edges (e.g. avformat -> swresample)
# need the fixpoint. Converges in 2 passes today; capped at 5.
needed=$(ldd target/release/meshharbord | awk '{print $1}')
for _pass in 1 2 3 4 5; do
  grew=0
  for real in $(find /opt/meshharbor-ffmpeg/lib -maxdepth 1 -type f -name 'lib*.so.*'); do
    soname=$(patchelf --print-soname "$real")
    [ -f "$dst/$soname" ] && continue
    if echo "$needed" | grep -qx "$soname"; then
      cp "$real" "$dst/$soname"
      grew=1
    fi
  done
  [ "$grew" = "1" ] || break
  needed=$(printf '%s\n' "$needed"; for l in "$dst"/lib*.so.*; do patchelf --print-needed "$l"; done)
done
copied=$(ls "$dst" | wc -l)
for real in $(find /opt/meshharbor-ffmpeg/lib -maxdepth 1 -type f -name 'lib*.so.*'); do
  soname=$(patchelf --print-soname "$real")
  [ -f "$dst/$soname" ] || echo "skipping unreferenced vendored lib: $soname"
done
# Floor = avcodec + avutil. With the MINIMAL vendored build the
# linker's --as-needed drops even avformat AND swresample from
# DT_NEEDED (the trimmed avcodec's pulled code never calls them;
# .pc Requires is a link-time statement, not a runtime one) — the
# first minimal rehearsal proved copied=2 is the correct steady
# state, and the earlier ">= 3" guard encoded the FULL build's
# linkage as law. Correctness is owned by the stock-24.04 load
# check below; this guard only catches a broken derivation (0-1
# matches = ldd/soname parsing went wrong).
[ "$copied" -ge 2 ] || { echo "::error::only $copied vendored FFmpeg libs matched — expected at least avcodec+avutil; the keep-set derivation is broken"; exit 1; }
# The agent binary ITSELF dynamically links libvpx.so.7 (the `vp9-444`
# VP9 software encoder — env-libvpx-sys links this build runner's
# libvpx-dev, which is 1.12 / libvpx.so.7 on ubuntu-22.04). Stock
# Ubuntu 24.04 ships only libvpx.so.9, so WITHOUT bundling this the
# .deb installs cleanly but the agent aborts at load with
# `libvpx.so.7: cannot open shared object file`. Carry it alongside the
# FFmpeg libs so the .deb runs on 22.04 (native) AND 24.04 (bundled).
vpx7=$(readlink -f /usr/lib/x86_64-linux-gnu/libvpx.so.7)
cp "$vpx7" "$dst/libvpx.so.7"
[ -f "$dst/libvpx.so.7" ] || { echo "::error::libvpx.so.7 not bundled — agent aborts at load on 24.04"; exit 1; }
# Each FFmpeg lib finds its siblings in the same dir ($ORIGIN); the
# binary finds them at the absolute install dir. Only glibc-family
# deps remain external (audited) — the HW encoders (nvenc/qsv/amf/
# vaapi/vulkan) dlopen their driver libs at runtime, so no extra
# .deb `depends` are needed.
for lib in "$dst"/*.so.*; do patchelf --set-rpath '$ORIGIN' "$lib"; done
# P3d Slice B: the daemon binary is now `meshharbord` (the [[bin]] output
# name); the .deb assets map installs it to /usr/lib/meshharbor-agent RPATH.
patchelf --set-rpath '/usr/lib/meshharbor-agent' target/release/meshharbord
echo "bundled: $(ls "$dst" | tr '\n' ' ')"
echo "binary RUNPATH -> $(patchelf --print-rpath target/release/meshharbord)"
```


### Archived step: Verify the bundled agent loads on stock Ubuntu 24.04 (original line 628)

```text
set -euo pipefail
docker run --rm -v "$PWD:/w" ubuntu:24.04 bash -euc '
  apt-get update -qq
  apt-get install -y -qq libxcb1 libxcb-shm0 libxcb-randr0 libasound2t64 >/dev/null
  LD_LIBRARY_PATH=/w/agents/meshharbord/vendor-ffmpeg /w/target/release/meshharbord --version
  # FR-77 P4 — the VA loader chain must come from the bundle: a stock
  # host has no libva2, and the daemon must still start there.
  for l in libva.so.2 libva-drm.so.2 libdrm.so.2; do
    test -f /w/agents/meshharbord/vendor-ffmpeg/$l || { echo "::error::$l missing from the bundle — the daemon would need the system libva"; exit 1; }
  done'
```


### Archived step: Build .deb (original line 642)

```text
cargo deb --no-build --no-strip
```


### Archived step: Guard — the daemon .deb stays headless (original line 657)

```text
set -euo pipefail
deb=$(ls target/debian/meshharbord_*_amd64.deb | head -n1)
depends=$(dpkg-deb -f "$deb" Depends)
echo "meshharbord Depends: $depends"
if echo "$depends" | grep -qiE 'webkit|gtk|appindicator|libx11|wayland'; then
  echo "::error::the meshharbord .deb grew a desktop dependency — the companion belongs in its own package (FR-27)"
  exit 1
fi
```


### Archived step: Rename + checksum (original line 670)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
# FR-21 P2a: cargo-deb emits `<package>_<version>_<arch>.deb`, and the
# package is `meshharbord`. FR-46 (#1051) took the DESTINATION name over
# too, after measuring every consumer rather than assuming: Windows
# keys on `.msi` + the `-permachine-` infix, macOS on `.pkg`, Linux
# >=0.4.16 on `is_daemon_asset` (which ALREADY accepts `meshharbord`),
# <=0.4.15 on the first `.deb` matching arch, `scripts/install.sh` on
# an arch+format SUFFIX, and the server-side ordering on a
# `meshharbor-desktop-` denylist. Not one of them keys on this prefix, so
# the rename freezes nothing. Already-published assets keep their old
# names and stay reachable through the legacy arm.
src=$(ls target/debian/meshharbord_*_amd64.deb | head -n1)
dst="meshharbord-${version}-x86_64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Stage the universal tarball (original line 697)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
sh scripts/stage-linux-tarball.sh "$version" x86_64-unknown-linux-gnu
echo "artifact=meshharbord-${version}-x86_64-unknown-linux-gnu.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Configure apt retries and refresh the index (original line 755)

```text
echo 'Acquire::Retries "3";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries
sudo apt-get update -qq
```


### Archived step: Verify the companion's build deps landed (fallback to apt-get) (original line 772)

```text
set -euo pipefail
pkgs="pkg-config libglib2.0-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev"
check() {
  sudo ldconfig
  for m in glib-2.0 gtk+-3.0 libsoup-3.0 javascriptcoregtk-4.1 webkit2gtk-4.1 ayatana-appindicator3-0.1; do
    pkg-config --exists "$m" || { echo "missing: pkg-config module $m"; return 1; }
  done
}
if ! check; then
  echo "::warning::the cached apt set did not deliver the companion's build deps; installing directly"
  sudo apt-get update -qq
  # shellcheck disable=SC2086
  sudo apt-get install -y $pkgs
fi
check || { echo "::error::companion build deps still missing after the fallback install"; exit 1; }
```


### Archived step: Install cargo-deb (original line 806)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
```


### Archived step: Install cargo-generate-rpm (original line 810)

```text
command -v cargo-generate-rpm >/dev/null || cargo install cargo-generate-rpm --locked
```


### Archived step: Build the desktop companion (original line 816)

```text
cargo build -p meshharbor-desktop --release
```


### Archived step: Build the companion .deb (original line 820)

```text
cargo deb --no-build --no-strip
```


### Archived step: Build the companion .rpm (original line 827)

```text
cargo generate-rpm -p agents/meshharbor-desktop
```


### Archived step: Guard — the companion .rpm requires what the binary links (original line 836)

```text
set -euo pipefail
sudo apt-get install -y -qq rpm >/dev/null
rpmf=$(find target/generate-rpm -name 'meshharbor-desktop-*.rpm' -print | head -n1)
[ -n "$rpmf" ] || { echo "::error::cargo generate-rpm produced no companion .rpm"; exit 1; }
rpm -qp --info "$rpmf" | grep -E '^(Name|Version|Release|Architecture)'
rpm -qp --info "$rpmf" | grep -qE '^Architecture: *x86_64' || { echo "::error::the companion .rpm is not x86_64"; exit 1; }
rpm -qp --requires "$rpmf" > rpm-requires.txt
cat rpm-requires.txt
missing=0
for so in $(readelf -d target/release/meshharbor-desktop | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
  case "$so" in ld-linux*) continue ;; esac
  if ! grep -qF "${so}()(64bit)" rpm-requires.txt; then
    echo "::error::the companion links $so, which its .rpm does not require: add it to [package.metadata.generate-rpm.requires]"
    missing=$((missing + 1))
  fi
done
if grep -qiE 'libicu|meshharbord' rpm-requires.txt; then
  echo "::error::the companion .rpm requires the daemon package or ICU by a name no RPM distro shares"
  missing=$((missing + 1))
fi
[ "$missing" -eq 0 ]
```


### Archived step: Rename + checksum (companion .deb and .rpm) (original line 862)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
# cargo-deb writes to the WORKSPACE target dir, but pin that with a
# find rather than a guess: a wrong path here fails the whole release
# job at its last step.
src=$(find . -path ./node_modules -prune -o \
             -name 'meshharbor-desktop_*_amd64.deb' -print | head -n1)
[ -n "$src" ] || { echo "::error::cargo deb produced no companion .deb"; exit 1; }
dst="meshharbor-desktop-${version}-x86_64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
# FR-93 P6d — the RPM under the same naming, so `install.sh` finds
# either by the one pattern with its extension swapped.
rsrc=$(find target/generate-rpm -name 'meshharbor-desktop-*.rpm' -print | head -n1)
[ -n "$rsrc" ] || { echo "::error::cargo generate-rpm produced no companion .rpm"; exit 1; }
rdst="meshharbor-desktop-${version}-x86_64-unknown-linux-gnu.rpm"
mv "$rsrc" "$rdst"
sha256sum "$rdst" | awk '{print $1"  "$2}' > "${rdst}.sha256"
echo "rpm=${rdst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Install system build deps (original line 924)

```text
sudo apt-get update
sudo apt-get install -y \
  pkg-config libglib2.0-dev libgtk-3-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev rpm
```


### Archived step: Install cargo-deb and cargo-generate-rpm (original line 944)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
command -v cargo-generate-rpm >/dev/null || cargo install cargo-generate-rpm --locked
```


### Archived step: Build the desktop companion (original line 949)

```text
cargo build -p meshharbor-desktop --release
```


### Archived step: Build the companion .deb (original line 953)

```text
cargo deb --no-build --no-strip
```


### Archived step: Build the companion .rpm (original line 956)

```text
cargo generate-rpm -p agents/meshharbor-desktop
```


### Archived step: Guard — the companion .rpm requires what the binary links (original line 960)

```text
set -euo pipefail
rpmf=$(find target/generate-rpm -name 'meshharbor-desktop-*.rpm' -print | head -n1)
[ -n "$rpmf" ] || { echo "::error::cargo generate-rpm produced no companion .rpm"; exit 1; }
rpm -qp --info "$rpmf" | grep -E '^(Name|Version|Release|Architecture)'
rpm -qp --info "$rpmf" | grep -qE '^Architecture: *aarch64' || { echo "::error::the arm64 companion .rpm is not aarch64"; exit 1; }
rpm -qp --requires "$rpmf" > rpm-requires.txt
cat rpm-requires.txt
missing=0
for so in $(readelf -d target/release/meshharbor-desktop | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
  case "$so" in ld-linux*) continue ;; esac
  if ! grep -qF "${so}()(64bit)" rpm-requires.txt; then
    echo "::error::the companion links $so, which its .rpm does not require: add it to [package.metadata.generate-rpm.requires]"
    missing=$((missing + 1))
  fi
done
if grep -qiE 'libicu|meshharbord' rpm-requires.txt; then
  echo "::error::the companion .rpm requires the daemon package or ICU by a name no RPM distro shares"
  missing=$((missing + 1))
fi
[ "$missing" -eq 0 ]
```


### Archived step: Rename + checksum (companion .deb and .rpm) (original line 985)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
src=$(find . -path ./node_modules -prune -o \
             -name 'meshharbor-desktop_*_arm64.deb' -print | head -n1)
[ -n "$src" ] || { echo "::error::cargo deb produced no arm64 companion .deb"; exit 1; }
dst="meshharbor-desktop-${version}-aarch64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
rsrc=$(find target/generate-rpm -name 'meshharbor-desktop-*.rpm' -print | head -n1)
[ -n "$rsrc" ] || { echo "::error::cargo generate-rpm produced no arm64 companion .rpm"; exit 1; }
rdst="meshharbor-desktop-${version}-aarch64-unknown-linux-gnu.rpm"
mv "$rsrc" "$rdst"
sha256sum "$rdst" | awk '{print $1"  "$2}' > "${rdst}.sha256"
echo "rpm=${rdst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Install system build deps (original line 1051)

```text
sudo apt-get update
sudo apt-get install -y \
  libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev \
  cmake libclang-dev pkg-config \
  libvpx-dev \
  libasound2-dev \
  patchelf
```


### Archived step: Install cargo-deb (original line 1088)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
```


### Archived step: Build agent (release, full + vp9-444, no ffmpeg-encoder) (original line 1093)

```text
cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ssh-server,viewer-indicator-x11"
```


### Archived step: Build the meshharbor CLI shim (shipped in the .deb alongside meshharbord) (original line 1096)

```text
set -euo pipefail
cargo build -p meshharbor-cli-shim --release
test -f target/release/meshharbor-shim || { echo "::error::meshharbor-shim not produced — the cargo-deb assets entry would fail"; exit 1; }
```


### Archived step: Bundle libvpx into the .deb (self-contained, RPATH) (original line 1102)

```text
set -euo pipefail
# Same ABI trap as the x86_64 lane: the agent links this runner's
# libvpx-dev (1.12 / libvpx.so.7 on 22.04) and stock 24.04 ships only
# libvpx.so.9, so without carrying it the .deb installs cleanly and
# then aborts at load. The cargo-deb assets glob is
# `vendor-ffmpeg/*.so.*` — CI-populated and shared with the x86_64
# lane's FFmpeg bundle; here it carries libvpx alone.
dst=agents/meshharbord/vendor-ffmpeg
rm -rf "$dst" && mkdir -p "$dst"
vpx7=$(readlink -f /usr/lib/aarch64-linux-gnu/libvpx.so.7)
cp "$vpx7" "$dst/libvpx.so.7"
[ -f "$dst/libvpx.so.7" ] || { echo "::error::libvpx.so.7 not bundled — agent aborts at load on 24.04"; exit 1; }
for lib in "$dst"/*.so.*; do patchelf --set-rpath '$ORIGIN' "$lib"; done
patchelf --set-rpath '/usr/lib/meshharbor-agent' target/release/meshharbord
echo "bundled: $(ls "$dst" | tr '\n' ' ')"
echo "binary RUNPATH -> $(patchelf --print-rpath target/release/meshharbord)"
```


### Archived step: Verify the bundled agent loads on stock Ubuntu 24.04 (arm64) (original line 1121)

```text
set -euo pipefail
docker run --rm -v "$PWD:/w" ubuntu:24.04 bash -euc '
  apt-get update -qq
  apt-get install -y -qq libxcb1 libxcb-shm0 libxcb-randr0 libasound2t64 >/dev/null
  LD_LIBRARY_PATH=/w/agents/meshharbord/vendor-ffmpeg /w/target/release/meshharbord --version'
```


### Archived step: Build .deb (original line 1130)

```text
cargo deb --no-build --no-strip
```


### Archived step: Rename + checksum (original line 1135)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
# FR-21 P2a: cargo-deb emits `<package>_<version>_<arch>.deb`, and the
# package is `meshharbord`. FR-46 (#1051) took the DESTINATION name over
# too, after measuring every consumer rather than assuming: Windows
# keys on `.msi` + the `-permachine-` infix, macOS on `.pkg`, Linux
# >=0.4.16 on `is_daemon_asset` (which ALREADY accepts `meshharbord`),
# <=0.4.15 on the first `.deb` matching arch, `scripts/install.sh` on
# an arch+format SUFFIX, and the server-side ordering on a
# `meshharbor-desktop-` denylist. Not one of them keys on this prefix, so
# the rename freezes nothing. Already-published assets keep their old
# names and stay reachable through the legacy arm.
src=$(ls target/debian/meshharbord_*_arm64.deb | head -n1)
dst="meshharbord-${version}-aarch64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Stage the universal tarball (original line 1158)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
sh scripts/stage-linux-tarball.sh "$version" aarch64-unknown-linux-gnu
echo "artifact=meshharbord-${version}-aarch64-unknown-linux-gnu.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Locate LLVM (provides libclang for bindgen) (original line 1234)

```text
# windows-latest ships LLVM (v20+) pre-installed under
# C:\Program Files\LLVM. Just point bindgen at it — don't try to
# downgrade via chocolatey (choco refuses without --allow-downgrade).
$llvm = "C:\Program Files\LLVM"
if (-not (Test-Path $llvm)) {
  choco install -y llvm
  $llvm = "C:\Program Files\LLVM"
}
"LIBCLANG_PATH=$llvm\bin" | Out-File -FilePath $env:GITHUB_ENV -Append
"$llvm\bin"              | Out-File -FilePath $env:GITHUB_PATH -Append
& "$llvm\bin\clang.exe" --version
```


### Archived step: Install pkg-config (env-libvpx-sys + ffmpeg-sys build scripts need it) (original line 1267)

```text
# `env-libvpx-sys` / `ffmpeg-sys-next` build.rs shell out to
# `pkg-config`; windows-latest ships none. We install vcpkg's
# `pkgconf` from the pre-installed vcpkg at C:\vcpkg (the ONLY
# remaining vcpkg use in this job — libvpx + FFmpeg are fetched
# prebuilt from the vendored-* releases below), so this pulls
# from the vcpkg registry, NOT SourceForge. The old `choco
# pkgconfiglite` downloaded its binary from SourceForge, which
# timed out and failed the rc.151 MSI build. Kept as a retried
# fallback.
$tools = 'C:\vcpkg\installed\x64-windows\tools\pkgconf'
$got = $false
# Cache hit: the tools dir is already on disk (including the
# pkg-config.exe alias, which was copied in before the save), so
# skip the vcpkg install entirely.
if (Test-Path "$tools\pkgconf.exe") {
  Write-Host "pkgconf restored from cache — skipping vcpkg install"
  Copy-Item "$tools\pkgconf.exe" "$tools\pkg-config.exe" -Force
  $tools | Out-File -FilePath $env:GITHUB_PATH -Append
  $env:PATH = "$tools;$env:PATH"
  $got = $true
}
if (-not $got -and (Test-Path 'C:\vcpkg\vcpkg.exe')) {
  C:\vcpkg\vcpkg.exe install pkgconf:x64-windows
  if (Test-Path "$tools\pkgconf.exe") {
    # The *-sys scripts invoke the command `pkg-config`; pkgconf is
    # a drop-in replacement, so expose it under that name too.
    Copy-Item "$tools\pkgconf.exe" "$tools\pkg-config.exe" -Force
    $tools | Out-File -FilePath $env:GITHUB_PATH -Append
    $env:PATH = "$tools;$env:PATH"
    $got = $true
  }
}
if (-not $got) {
  Write-Host "vcpkg pkgconf unavailable — falling back to choco pkgconfiglite (SourceForge; retried)"
  for ($i = 1; $i -le 3; $i++) {
    choco install -y pkgconfiglite
    if (Get-Command pkg-config -ErrorAction SilentlyContinue) { break }
    Write-Host "pkgconfiglite attempt $i failed (likely SourceForge); retrying in 15s"
    Start-Sleep -Seconds 15
  }
}
# Tells the save step below whether there is actually a vcpkg-shaped
# tools dir worth caching (the choco fallback leaves it empty).
# NB `hashFiles()` can't be used for this: it only globs inside
# GITHUB_WORKSPACE, so it would silently return '' for a C:\vcpkg
# path and the save would never run.
$hasVcpkgPkgconf = if (Test-Path (Join-Path $tools 'pkgconf.exe')) { 'true' } else { 'false' }
"vcpkg_pkgconf=$hasVcpkgPkgconf" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
# Fails the step loudly if neither path produced a usable pkg-config.
pkg-config --version
```


### Archived step: Fetch vendored libvpx 1.12.0 (matches pre-generated bindings) (original line 1334)

```text
$ErrorActionPreference = 'Stop'
# We DON'T enable `vp9-444-bindgen` on Windows because bindgen
# 0.68.1 + libclang on Windows has a regression that opaques
# `vpx_codec_enc_cfg` (forward-declared in vpx_codec.h's union
# before its full def in vpx_encoder.h) — every field becomes
# `_address: u8` and the build collapses. Local-repro confirms
# this on libvpx 1.12 / 1.13 / 1.16 alike, so it's not a
# libvpx-version issue, it's a Windows-libclang issue.
#
# Workaround: skip bindgen entirely. env-libvpx-sys ships
# pre-generated FFI for libvpx 1.3.0–1.13.0 and its build.rs
# picks the file matching pkg-config's reported version EXACTLY
# — hence the 1.12.0 pin. Built once by vendor-libvpx-windows.yml
# (same manifest/baseline/triplet the inline vcpkg build used)
# and fetched here in seconds instead of ~5 min of vcpkg compile
# per tag — same pattern as the vendored FFmpeg below.
$dl = "$env:RUNNER_TEMP\vpxdl"
gh release download vendored-libvpx-1.12.0 --repo "${{ github.repository }}" `
  --pattern 'libvpx-1.12.0-win64-msvc.zip*' --dir $dl
$zip = "$dl\libvpx-1.12.0-win64-msvc.zip"
$expected = ((Get-Content "$zip.sha256" -Raw).Trim() -split '\s+')[0].ToLower()
$actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if ($actual -ne $expected) { Write-Host "::error::vendored libvpx sha256 mismatch (got $actual, want $expected)"; exit 1 }
# Extract to the EXACT tree the old inline vcpkg build produced so
# the baked .pc paths + the env exports below stay valid.
$root = 'C:\vpx-pin\installed\x64-windows'
New-Item -ItemType Directory -Path $root -Force | Out-Null
tar -xf $zip -C $root
if (-not (Test-Path "$root\lib\pkgconfig\vpx.pc")) { Write-Host "::error::vpx.pc missing after extract"; exit 1 }
# Expose the install dir to subsequent steps.
"PKG_CONFIG_PATH=C:/vpx-pin/installed/x64-windows/lib/pkgconfig" | Out-File -FilePath $env:GITHUB_ENV -Append
# The x64-windows libvpx port yields a static .lib only (no DLL),
# so the staging step below no-ops; the env stays for the day the
# port grows a bin/ again.
"VPX_DLL_DIR=C:/vpx-pin/installed/x64-windows/bin" | Out-File -FilePath $env:GITHUB_ENV -Append
```


### Archived step: Fetch vendored FFmpeg 9.0.1 (win64 static-md, LGPL, minimal) (original line 1388)

```text
$ErrorActionPreference = 'Stop'
$dl = "$env:RUNNER_TEMP\ffdl"
# P3e lever B: the MINIMAL tree — --disable-everything + exactly the
# ten HW encoders the agent dispatches (avcodec.lib 139.3 -> 12.1 MB;
# vendor-ffmpeg-windows.yml's verify step asserts the symbol set).
# Rollback = drop the `-minimal` suffix here; the full zip stays on
# the same release untouched. FR-78 P0 added `-d3d12-vulkan` (six
# more encoders, both backends dlopen'd by FFmpeg — no new import);
# rollback = drop that suffix. FR-85 P4c added `-h264dec-aac` (the
# software h264 decoder the recorder's editor needs and the aac
# encoder for its sound; no new import); rollback = drop that one.
gh release download vendored-ffmpeg-9.0.1 --repo "${{ github.repository }}" `
  --pattern 'ffmpeg-9.0.1-win64-msvc-static-md-lgpl-minimal-d3d12-vulkan-h264dec-aac.zip*' --dir $dl
$zip = "$dl\ffmpeg-9.0.1-win64-msvc-static-md-lgpl-minimal-d3d12-vulkan-h264dec-aac.zip"
$expected = ((Get-Content "$zip.sha256" -Raw).Trim() -split '\s+')[0].ToLower()
$actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if ($actual -ne $expected) { Write-Host "::error::vendored FFmpeg sha256 mismatch (got $actual, want $expected)"; exit 1 }
# Extract to the EXACT tree the old inline vcpkg build produced so
# the baked .pc paths + every downstream step (PKG_CONFIG_PATH
# append, static-md no-op DLL staging) stay valid. bsdtar handles
# zip and is much faster than Expand-Archive. (If bsdtar ever
# chokes on Compress-Archive's backslash entry names, swap to
# Expand-Archive — the .pc assert below catches it loudly.)
$root = 'C:\ffmpeg-pin\installed\x64-windows-static-md'
New-Item -ItemType Directory -Path $root -Force | Out-Null
tar -xf $zip -C $root
foreach ($pc in 'libavcodec.pc', 'libavutil.pc') {
  if (-not (Test-Path "$root\lib\pkgconfig\$pc")) { Write-Host "::error::$pc missing after extract"; exit 1 }
}
Write-Host "FFmpeg pkg-config files present at $root\lib\pkgconfig\"
# ── FR-62 A2 drift gate (Windows twin — see the Linux job): assert
#    the vendored libs were built from the committed FFmpeg source
#    patches. The vcpkg overlay build wrote MESHHARBOR-PATCHES.txt
#    (sha256 per patch) into the zip root. Fail closed on mismatch or
#    an absent manifest while patches exist — a stale vendored asset
#    must never ship. Fix = re-run vendor-ffmpeg-windows.yml.
$committed = Get-ChildItem "$env:GITHUB_WORKSPACE\.github\ffmpeg-patches\*.patch" -ErrorAction SilentlyContinue
if ($committed) {
  $want = $committed | ForEach-Object {
    "{0} {1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $_.Name
  } | Sort-Object
  $manifestPath = "$root\MESHHARBOR-PATCHES.txt"
  if (-not (Test-Path $manifestPath)) {
    Write-Host "::error::vendored FFmpeg carries no MESHHARBOR-PATCHES.txt but $($committed.Count) patch(es) are committed — re-vendor before tagging"; exit 1
  }
  $got = Get-Content $manifestPath | Where-Object { $_.Trim() -ne '' } | ForEach-Object {
    $parts = $_ -split '\s+', 2
    "{0} {1}" -f $parts[0].ToLower(), $parts[1].Trim()
  } | Sort-Object
  if (($want -join "`n") -ne ($got -join "`n")) {
    Write-Host "::error::vendored FFmpeg patch manifest != committed .github/ffmpeg-patches/ — re-run vendor-ffmpeg-windows.yml"
    Write-Host "--- committed ---"; $want | ForEach-Object { Write-Host $_ }
    Write-Host "--- in asset ---"; $got | ForEach-Object { Write-Host $_ }
    exit 1
  }
  Write-Host "FR-62 A2 gate OK: vendored FFmpeg built from $($committed.Count) committed patch(es)"
}
```


### Archived step: Append FFmpeg to PKG_CONFIG_PATH + DLL PATH (original line 1449)

```text
# libvpx step already set PKG_CONFIG_PATH=C:/vpx-pin/...; ffmpeg
# needs to extend, not replace. Read current value, append ffmpeg
# path, write back. Windows pkg-config uses ';' as separator.
$existing = [Environment]::GetEnvironmentVariable('PKG_CONFIG_PATH', 'Process')
if ([string]::IsNullOrEmpty($existing)) { $existing = "" } else { $existing = "$existing;" }
$combined = "${existing}C:/ffmpeg-pin/installed/x64-windows-static-md/lib/pkgconfig"
"PKG_CONFIG_PATH=$combined" | Out-File -FilePath $env:GITHUB_ENV -Append
Write-Host "PKG_CONFIG_PATH=$combined"
# rc.71 hotfix: vcpkg's x64-windows triplet produces DLLs for
# ffmpeg (libavcodec-*.dll etc.), not static libs. The agent test
# binary links against them at compile time but Windows can't
# find them at runtime (STATUS_DLL_NOT_FOUND, 0xc0000135 — rc.69
# CI failure). Add the ffmpeg bin dir to GITHUB_PATH so cargo test
# picks it up. Also stash for the MSI staging step below.
"C:\ffmpeg-pin\installed\x64-windows-static-md\bin" | Out-File -FilePath $env:GITHUB_PATH -Append
"FFMPEG_DLL_DIR=C:\ffmpeg-pin\installed\x64-windows-static-md\bin" | Out-File -FilePath $env:GITHUB_ENV -Append
```


### Archived step: Install WiX Toolset v3 (original line 1492)

```text
choco install -y wixtoolset
# WiX v3 installs to C:\Program Files (x86)\WiX Toolset v3.14\bin by
# default — add to PATH for this and subsequent steps.
$wixBin = Get-ChildItem "C:\Program Files (x86)\WiX Toolset v*\bin" | Select-Object -First 1
"$($wixBin.FullName)" | Out-File -FilePath $env:GITHUB_PATH -Append
```


### Archived step: Install cargo-wix (original line 1503)

```text
if (-not (Get-Command cargo-wix -ErrorAction SilentlyContinue)) {
  cargo install cargo-wix --locked
}
```


### Archived step: Build agent (release, full-hw + vp9-444 + system-context + ffmpeg-encoder) (original line 1549)

```text
cargo build -p meshharbord --release --features "full-hw,hive,vp9-444,system-context,ffmpeg-encoder,overlay-l3,overlay-netstack,ssh-server"
```


### Archived step: Build the meshharbor CLI shim for the MSI bundle (P3e lever D) (original line 1553)

```text
# P4b put the tunnel CLI inside both MSIs so daemon installs subsume
# it and the MSI stays the ONE updater for the node stack. That is
# unchanged — what changed (P3e lever D) is HOW: the daemon now owns
# the command surface (`meshharbord cli` → meshharbor_cli::cli) and the
# MSI carries a ~150 KB shim instead of a second full binary.
#
# rc.361 measurements that motivated it: mh.exe was 22.1 MiB of
# which cargo-bloat attributes only 1.16 MiB to CLI-specific code —
# the rest duplicated std/webrtc/tunnel_core/tokio/rustls/reqwest/
# quinn/clap that meshharbord.exe already links. This step also used to
# cost 143 s (3rd-costliest in the job) because it rebuilt shared
# deps under a DIFFERENT feature set than the agent build above.
#
# Both wxs files reference target\release\meshharbor-shim.exe at harvest
# time, so this MUST still run before the two cargo-wix builds below.
# Tunnel-ONLY hosts are unaffected: release-tunnel.yml keeps building
# and shipping the real standalone `mh` binary.
cargo build -p meshharbor-cli-shim --release
if (-not (Test-Path target\release\meshharbor-shim.exe)) {
  Write-Host "::error::meshharbor-shim.exe not produced — the TunnelExe wxs component would fail the MSI harvest (LGHT0103)"
  exit 1
}
$kb = [math]::Round((Get-Item target\release\meshharbor-shim.exe).Length/1KB, 0)
Write-Host "Staged meshharbor-shim.exe ($kb KB, installs as mh.exe) for the TunnelExe component"
```


### Archived step: Stage vpx.dll alongside agent binary (if not statically linked) (original line 1589)

```text
# vcpkg's `x64-windows` triplet for libvpx produces a static
# .lib + .pdb only — no .dll. The agent binary links libvpx
# statically and runs without a separate DLL. If a future
# vcpkg port (or a triplet swap) produces a vpx.dll, copy it
# next to meshharbor-agent.exe so cargo-wix harvests it. No-op
# when the DLL isn't there.
$dll = Join-Path $env:VPX_DLL_DIR "vpx.dll"
if (Test-Path $dll) {
  Copy-Item $dll target\release\
  Write-Host "Staged vpx.dll for MSI harvest"
} else {
  Write-Host "No vpx.dll under $env:VPX_DLL_DIR — static linkage, nothing to stage"
}
```


### Archived step: Stage FFmpeg DLLs alongside agent binary (no-op for static-md) (original line 1611)

```text
if (-not (Test-Path $env:FFMPEG_DLL_DIR)) {
  Write-Host "No bin dir under $env:FFMPEG_DLL_DIR — static-md triplet, nothing to stage."
  exit 0
}
$dlls = Get-ChildItem -Path $env:FFMPEG_DLL_DIR -Filter "*.dll"
if ($dlls.Count -eq 0) {
  Write-Host "No DLLs under $env:FFMPEG_DLL_DIR — static-md triplet, nothing to stage."
  exit 0
}
foreach ($dll in $dlls) {
  Copy-Item $dll.FullName target\release\
}
Write-Host "Staged $($dlls.Count) FFmpeg DLLs for MSI harvest:"
foreach ($dll in $dlls) {
  Write-Host "  $($dll.Name) ($([math]::Round($dll.Length / 1KB, 0)) KB)"
}
```


### Archived step: Encoder smoke test (FFmpeg link check + MF cascade → openh264 fallback) (original line 1633)

```text
# Probe the hardware encoder path. On windows-latest the runner
# exposes a WARP software D3D11 device; the MS H264 Encoder MFT
# falls back to its SW path there, which is enough for "it loads,
# negotiates types, produces an IDR, no SEH crash". Debug logging
# surfaces STREAM_CHANGE notifications and per-frame byte counts
# so regressions in the MF drain path are visible in CI output.
# P3d Slice B: daemon EXE is now meshharbord.exe.
# Under ffmpeg-encoder, encoder-smoke FIRST asserts the linked
# libavcodec is >= 61 (FFmpeg 7+) — the load-bearing replacement
# for the deleted 5m33s cargo-test link-verify step. On failure:
# re-pin ffmpeg-next in agents/meshharbord/Cargo.toml or
# re-vendor via vendor-ffmpeg-windows.yml.
& "target\release\meshharbord.exe" encoder-smoke --encoder hardware
```


### Archived step: Stage wintun.dll for the overlay TUN (overlay-l3 MSI bundle) (original line 1694)

```text
# overlay-l3's Windows TUN is Wintun, whose signed wintun.dll is
# LoadLibrary'd at runtime from the app dir. Fetch the official
# build (WireGuard LLC, Authenticode-signed) and stage the amd64
# DLL next to the EXE so the `WintunDll` wxs component (in both
# wix/ + wix-perMachine/) bundles it into both MSIs. The build
# above includes overlay-l3, so the agent will LoadLibrary this.
$ver = '0.14.1'
$zip = "$env:RUNNER_TEMP\wintun.zip"
Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$ver.zip" -OutFile $zip -UseBasicParsing
$dest = "$env:RUNNER_TEMP\wintun"
Expand-Archive -Path $zip -DestinationPath $dest -Force
$dll = Join-Path $dest 'wintun\bin\amd64\wintun.dll'
if (-not (Test-Path $dll)) { Write-Host "::error::wintun.dll (amd64) not found in the downloaded archive"; exit 1 }
$sig = Get-AuthenticodeSignature $dll
Write-Host "wintun.dll signature: $($sig.Status) -- signer: $($sig.SignerCertificate.Subject)"
Copy-Item $dll target\release\wintun.dll -Force
Write-Host "Staged wintun.dll ($([math]::Round((Get-Item target\release\wintun.dll).Length/1KB,0)) KB) for the MSI bundle"
```


### Archived step: Stage VC++ runtime DLLs alongside agent binary (app-local CRT) (original line 1715)

```text
# Both wxs files bundle a `VcRedistCrt` component (the three CRT
# DLLs our binaries actually import) so the install is
# self-contained on machines without any VC++ 2015-2022
# redistributable -- a fresh Windows box otherwise pops
# "vcruntime140_1.dll was not found" the moment install.ps1
# (or the operator) runs the freshly installed meshharbord.exe,
# which links the CRT dynamically via its C++ encoder objects
# (field report 2026-07-28). The DLLs come from the runner's
# own VS installation; fail loudly if any expected name is
# absent (the WiX harvest would die with LGHT0103 later
# anyway). Mirrored in installer-smoke.yml.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { Write-Host "::error::vswhere.exe not found on the runner"; exit 1 }
$vsRoot = & $vswhere -latest -products * -property installationPath
$crtDir = Get-ChildItem -Directory "$vsRoot\VC\Redist\MSVC\*\x64\Microsoft.VC14*.CRT" -ErrorAction SilentlyContinue |
          Sort-Object FullName | Select-Object -Last 1
if (-not $crtDir) { Write-Host "::error::no Microsoft.VC14x.CRT redist folder under $vsRoot"; exit 1 }
# Only what the import tables ask for: meshharbord.exe needs all three,
# mh.exe needs vcruntime140, meshharbor-desktop.exe needs none, and
# msvcp140.dll itself imports only the two vcruntime DLLs. The other
# six redist DLLs (concrt140, vccorlib140, msvcp140_1, msvcp140_2,
# msvcp140_atomic_wait, msvcp140_codecvt_ids) are satellites a
# consuming binary imports DIRECTLY when it uses the matching STL
# feature; nothing we ship does, so they were 1.12 MiB of dead
# payload per install. If a new C++ dependency lands, re-check with
# `dumpbin -dependents target\release\meshharbord.exe | findstr /i 140`
# and extend this list AND both wxs VcRedistCrt components together.
$expected = @('msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll')
foreach ($n in $expected) {
  $src = Join-Path $crtDir.FullName $n
  if (-not (Test-Path $src)) { Write-Host "::error::$n missing from $($crtDir.FullName) -- VcRedistCrt harvest would fail (LGHT0103)"; exit 1 }
  Copy-Item $src target\release\ -Force
}
Write-Host "Staged $($expected.Count) VC++ runtime DLLs from $($crtDir.FullName)"
```


### Archived step: Build MSI (per-User) (original line 1753)

```text
# cargo-wix reads agents/meshharbord/wix/main.wxs and sets the
# Version preprocessor variable from --install-version.
cargo wix -p meshharbord --nocapture --no-build --install-version $env:MSI_VERSION
```


### Archived step: Locate + rename per-User MSI (original line 1761)

```text
$msi = Get-ChildItem "target/wix/*.msi" | Select-Object -First 1
if (-not $msi) { throw "per-User MSI not produced" }
# No `-unsigned` suffix. It used to be derived from whether a secret
# was set, computed BEFORE signtool ran, so it described the repo's
# configuration rather than the bytes. Signedness now comes from the
# sign-windows action's verify step, which fails the job on a
# release run. Consumers are suffix-agnostic in both directions
# (agent_release.rs / updater.rs match on ".msi" + the
# "-permachine-" infix), so older published releases keep resolving.
$dst = "meshharbord-$env:VERSION-x86_64-pc-windows-msvc.msi"
Move-Item $msi.FullName $dst
"artifact=$dst" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Build MSI (per-Machine) (original line 1777)

```text
# cargo-wix auto-discovers every *.wxs under wix/, so the
# per-Machine source lives in a sibling wix-perMachine/ dir
# to keep it OUT of the per-User build's compile set.
# For this run we copy that file over wix/main.wxs (after
# backing up the original), invoke cargo wix again, and
# restore. Both MSIs end up in target/wix/ and we rename
# to disambiguate. Different UpgradeCode + the mutually-
# exclusive LaunchConditions ensure a host can only ever
# have one of the two installed at a time.
$wixDir = "agents\meshharbord\wix"
$pmSrc  = "agents\meshharbord\wix-perMachine\main.wxs"
Copy-Item "$wixDir\main.wxs" "$wixDir\main.wxs.bak" -Force
Copy-Item $pmSrc "$wixDir\main.wxs" -Force
try {
  cargo wix -p meshharbord --nocapture --no-build --install-version $env:MSI_VERSION
} finally {
  Move-Item "$wixDir\main.wxs.bak" "$wixDir\main.wxs" -Force
}
```


### Archived step: Locate + rename per-Machine MSI (original line 1800)

```text
$msi = Get-ChildItem "target/wix/*.msi" | Select-Object -First 1
if (-not $msi) { throw "per-Machine MSI not produced" }
# Suffix-free -- see the per-User rename above.
$dst = "meshharbord-$env:VERSION-perMachine-x86_64-pc-windows-msvc.msi"
Move-Item $msi.FullName $dst
"artifact=$dst" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Assert third-party DLLs keep their original signatures (original line 1838)

```text
$checks = @(
  @{ Path = 'target\release\wintun.dll';        Want = '*WireGuard*' },
  @{ Path = 'target\release\vcruntime140.dll';  Want = '*Microsoft*' }
)
foreach ($c in $checks) {
  $sig = Get-AuthenticodeSignature $c.Path
  $cn = if ($sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { '<none>' }
  Write-Host "$(Split-Path -Leaf $c.Path) signer: $cn (status=$($sig.Status))"
  if ($cn -notlike $c.Want) {
    Write-Host "::error::$($c.Path) is no longer signed by its original publisher (got '$cn'). The MSI payload-signing step must never include third-party DLLs."
    exit 1
  }
}
```


### Archived step: Assert the shipping MSIs are self-contained (PE import audit) (original line 1855)

```text
# The Windows half of the check that would have caught the macOS
# .pkg which crashed on every clean Mac until rc.453: a dependency
# satisfied by the BUILD machine is invisible to any check that runs
# on the build machine. `windows-latest` carries the VC redist — it
# is where the CRT staging step SOURCES those DLLs from — so
# launching a binary here proves nothing about a fresh host.
#
# installer-smoke.yml (#647) audits an INSTALLED per-User MSI. This
# is the same audit on the artifacts that actually ship, and it is
# not redundant with that one:
#   - installer-smoke builds a MINIMAL feature set; this job builds
#     full-hw + vp9-444 + system-context + ffmpeg-encoder, which is
#     where a new native dependency would actually appear.
#   - it covers per-Machine too, a SEPARATE wxs whose component list
#     can drift from the per-User one.
#   - it reads the MSI, not `target\release\`. Auditing the staging
#     directory would pass on a DLL that is staged but never
#     harvested into a wxs component — i.e. exactly the bug where
#     the install is missing a file the build had.
#
# ⚠️ This arms on a workflow_dispatch as well as on a tag, on
# purpose. #639: `publish_release=false` does not exercise the
# tag-only gates, so they are unrehearsable and first run when a
# release is on the line. A gate you cannot rehearse is a gate you
# find out about at the worst moment.
$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsRoot  = & $vswhere -latest -products * -property installationPath
$dumpbin = Get-ChildItem -Path "$vsRoot\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" |
           Sort-Object FullName | Select-Object -Last 1
if (-not $dumpbin) { throw "dumpbin.exe not found under $vsRoot" }

# Redistributables — shipped by us, never by Windows. These MUST be
# app-local; finding them in System32 proves nothing about a fresh
# machine, so they are excluded from the System32 allowance below.
$mustBeAppLocal = '^(msvcp|vcruntime|concrt|mfc|vcomp|msvcr)'

function Audit-Dir {
  param([string]$Dir, [switch]$Quiet)
  $found    = @()
  $appLocal = @()
  foreach ($exe in @('meshharbord.exe', 'mh.exe')) {
    $path = Join-Path $Dir $exe
    if (-not (Test-Path $path)) { $found += "$exe missing from the MSI payload"; continue }
    $imports = & $dumpbin /dependents $path |
      Select-String -Pattern '^\s{4}(\S+\.dll)$' |
      ForEach-Object { $_.Matches[0].Groups[1].Value }
    if (-not $imports) { $found += "$exe : dumpbin listed no imports (parse broke?)"; continue }
    if (-not $Quiet) { Write-Host "  $exe imports $($imports.Count) DLLs" }
    foreach ($dll in $imports) {
      if (Test-Path (Join-Path $Dir $dll)) { $appLocal += $dll; continue }
      if ($dll -match $mustBeAppLocal) {
        $found += "$exe -> $dll is a REDISTRIBUTABLE and the MSI does not ship it"
        continue
      }
      if ($dll -match '^(api-ms-win-|ext-ms-win-)') { continue }
      if (Test-Path (Join-Path $env:SystemRoot 'System32' $dll)) { continue }
      $found += "$exe -> $dll is neither in the MSI nor an OS DLL"
    }
  }
  [pscustomobject]@{
    Problems = @($found)
    AppLocal = @($appLocal | Sort-Object -Unique)
  }
}

$flavours = @(
  @{ Name = 'per-User';    Msi = '${{ steps.locate.outputs.artifact }}' },
  @{ Name = 'per-Machine'; Msi = '${{ steps.locate_pm.outputs.artifact }}' }
)

$lastDir      = $null
$lastAppLocal = @()
foreach ($f in $flavours) {
  Write-Host "--- 1/2: $($f.Name) MSI payload must be self-contained ---"
  $out = Join-Path $env:RUNNER_TEMP "msi-audit\$($f.Name)"
  Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  # /a is an ADMINISTRATIVE install: it lays the payload out on disk
  # without installing, registering or running anything.
  $msiPath = (Resolve-Path $f.Msi).Path
  $p = Start-Process msiexec.exe -Wait -PassThru `
         -ArgumentList @('/a', "`"$msiPath`"", '/qn', "TARGETDIR=`"$out`"")
  if ($p.ExitCode -ne 0) { throw "msiexec /a failed for $($f.Name) with exit $($p.ExitCode)" }

  $hit = Get-ChildItem -Recurse $out -Filter 'meshharbord.exe' -File | Select-Object -First 1
  if (-not $hit) { throw "meshharbord.exe not found in the extracted $($f.Name) payload" }
  $installDir = $hit.DirectoryName
  Write-Host "  payload dir: $($installDir.Substring($out.Length))"

  $r = Audit-Dir -Dir $installDir
  if ($r.Problems.Count -gt 0) {
    $r.Problems | ForEach-Object { Write-Host "::error::[$($f.Name)] $_" }
    throw "$($f.Name) MSI is not self-contained"
  }
  Write-Host "  OK: every import is shipped in the MSI or by Windows"
  Write-Host "  MSI-shipped imports: $($r.AppLocal -join ', ')"
  $lastDir = $installDir
  $lastAppLocal = $r.AppLocal
}

# ⚠️ A gate proven only on the passing case is the failure mode this
# step exists to fix — "it printed OK" is not evidence it can say
# anything else. Hide a shipped DLL and require a complaint. The
# victim is chosen from what the binaries ACTUALLY import rather
# than named up front: hard-coding msvcp140 is precisely how the
# first version of the installer-smoke control passed vacuously.
Write-Host '--- 2/2: negative control — removing a shipped import must FAIL the audit ---'
if ($lastAppLocal.Count -eq 0) {
  throw "NEGATIVE CONTROL IMPOSSIBLE: no imported DLL is shipped in the MSI, so this audit has nothing to detect. Either the CRT bundle is unnecessary in this build, or the dumpbin parse is wrong — both need a human."
}
$victim = Join-Path $lastDir $lastAppLocal[0]
$stash  = "$victim.hidden"
Write-Host "  hiding $($lastAppLocal[0])"
Move-Item $victim $stash
try {
  $neg = Audit-Dir -Dir $lastDir -Quiet
  if ($neg.Problems.Count -eq 0) {
    throw "NEGATIVE CONTROL FAILED: $($lastAppLocal[0]) was removed and the audit still passed — this check cannot detect what it claims to."
  }
  Write-Host "  OK: audit reported $($neg.Problems.Count) problem(s): $($neg.Problems[0])"
} finally {
  Move-Item $stash $victim
}
```


### Archived step: Verify MSI size budget (P4b: MSI carries the tunnel CLI) (original line 1995)

```text
$msiPerUser = (Get-Item "${{ steps.locate.outputs.artifact }}").Length / 1MB
$msiPerMachine = (Get-Item "${{ steps.locate_pm.outputs.artifact }}").Length / 1MB
$maxMsi = [math]::Max($msiPerUser, $msiPerMachine)
# P3e lever D re-baseline. rc.361 measured 31.97 MB with the full
# 22.1 MiB tunnel CLI inside; the CLI's compressed contribution was
# ~7.6 MB (measured as the rc.194 -> rc.195 step when P4b added it),
# and the shim that replaces it is ~0.15 MB. Ceiling drops with it:
# 36 -> 30 MB, keeping the same ~5 MB of headroom over the baseline
# that the P4b guard had.
# Baseline PINNED from the P3e Phase-2 rehearsal (run 31869144675,
# 2026-08-15, lever-B rehearsal 31877551270): both flavours measured
# 13.13 MB (minimal vendored FFmpeg). A baseline left above the real value is
# exactly the silent failure this guard exists to catch — it would
# swallow a multi-MB regression as "within budget".
# MeshHarbor SSH (`ssh-server`) is a DELIBERATE growth on top of that
# baseline: russh measured +1.86 MiB in meshharbord, ~+0.7 MB
# compressed here. That stays inside the +2 warn band, so the guard
# is deliberately NOT re-pinned in the same commit that adds it —
# re-pin from the first measured release run, never from an
# estimate, or the baseline swallows exactly the regression it
# exists to catch.
# FR-85 P4c re-baseline (AC9): the screen recorder and its FFmpeg
# (the h264 decoder + the aac encoder) are DELIBERATE scope. The
# unpublished rehearsal of that branch (run 36346825023, 2026-09-27)
# measured both flavours at 17.67 MB: 0.4.105 (no recorder) was 15.89,
# the canary with `recording` 17.04, and P4c + everything merged
# since then +0.63. The old 13.13 baseline had fired the warning on
# every release since ssh-server, which is noise, not a signal.
# The ceiling moves 18 -> 22 with it. Against a 17.67 baseline, an 18
# ceiling sat INSIDE the +2 warn band, so any growth hard-failed a
# tag with no warning a release earlier, the opposite of this guard's
# design. 22 restores warn (19.67) before fail, with ~4.3 MB of
# headroom (the guard has kept ~5 over its baseline since P4b).
$p4bBaseline = 17.67
$ceilingMB = 22
$deltaMB = $maxMsi - $p4bBaseline
Write-Host "::notice::per-User MSI = $([math]::Round($msiPerUser, 2)) MB"
Write-Host "::notice::per-Machine MSI = $([math]::Round($msiPerMachine, 2)) MB"
Write-Host "::notice::baseline = $p4bBaseline MB; delta = $([math]::Round($deltaMB, 2)) MB"
if ($maxMsi -gt $ceilingMB) {
  Write-Host "::error::MSI exceeds the $ceilingMB MB hard ceiling ($([math]::Round($maxMsi, 2)) MB). Investigate unintended payload growth (unstripped FFmpeg, extra DLLs, debug info, or a full CLI binary back in the TunnelExe component)."
  exit 1
} elseif ($deltaMB -gt 2) {
  Write-Host "::warning::MSI is $([math]::Round($deltaMB, 2)) MB over the baseline (still under the $ceilingMB MB ceiling). Re-baseline deliberately or investigate."
} else {
  Write-Host "::notice::MSI within the P4b size budget."
}
```


### Archived step: SHA256 checksum (both MSIs) (original line 2052)

```text
$files = @(
  "${{ steps.locate.outputs.artifact }}",
  "${{ steps.locate_pm.outputs.artifact }}"
)
foreach ($f in $files) {
  $hash = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
  "$hash  $f" | Out-File -Encoding ascii "$f.sha256"
}
```


### Archived step: Build tray binary (release) (original line 2160)

```text
cargo build -p meshharbor-desktop --release
```


### Archived step: Locate + rename tray EXE (original line 2165)

```text
# P3d Slice B: the tray/desktop-companion OUTPUT binary is now
# `meshharbor-desktop.exe` (and since FR-21 P2a the package matches). The
# released artifact is renamed to match.
$exe = "target/release/meshharbor-desktop.exe"
if (-not (Test-Path $exe)) { throw "meshharbor-desktop EXE not produced" }
# Suffix-free: signedness is verified, not encoded in the filename.
# install.ps1's `-like 'meshharbor-desktop-*-x86_64-pc-windows-msvc*.exe'`
# and asset_resolver.rs's contains/ends_with both still match.
$dst = "meshharbor-desktop-$env:VERSION-x86_64-pc-windows-msvc.exe"
Copy-Item $exe $dst
"artifact=$dst" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: SHA256 checksum (desktop companion) (original line 2201)

```text
$files = @(
  "${{ steps.locate_tray.outputs.artifact }}"
)
foreach ($f in $files) {
  $hash = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
  "$hash  $f" | Out-File -Encoding ascii "$f.sha256"
}
```


### Archived step: Build the desktop companion (original line 2282)

```text
cargo build -p meshharbor-desktop --release --target aarch64-apple-darwin
```


### Archived step: Resolve Apple signing mode (original line 2356)

```text
set -euo pipefail
req=(APP_P12_BASE64 INSTALLER_P12_BASE64 CERT_PASSWORD
     APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8_BASE64)
have=(); miss=()
for v in "${req[@]}"; do
  if [[ -n "${!v:-}" ]]; then have+=("$v"); else miss+=("$v"); fi
done

if [[ ${#miss[@]} -eq 0 ]]; then
  mode=full
elif [[ ${#have[@]} -eq 0 ]]; then
  mode=none
else
  echo "::error::Apple credentials are PARTIALLY configured (missing: ${miss[*]}). Signing is all-or-nothing: a half-configured run can only produce a signed-but-unnotarised or an unsigned-but-pkg-signed artifact, both of which Gatekeeper rejects. Run scripts/signing/60-apple-setup.sh check."
  exit 1
fi

if [[ "$mode" == none ]]; then
  # Deliberately a WARNING, not a failure, until Apple enrolment
  # completes (blocked on D-U-N-S — scripts/signing/60-apple-setup.sh).
  #
  # This gate hard-failed release tags when it landed with #599, and
  # the cost was out of all proportion to the risk: agent-v0.3.0-rc.453
  # died here after 10 seconds, and because `Publish GitHub Release`
  # needs every build job, it took the four HEALTHY lanes with it —
  # the .deb x86_64, the .deb aarch64, the .msi and the companion EXE
  # had all built successfully and none of them was published. One
  # unconfigured platform must not be able to stop the fleet's releases.
  #
  # The premise was also too strong. Gatekeeper's assessment is
  # triggered by the com.apple.quarantine xattr, which a browser sets
  # and `curl` does not, so the path our own installer uses —
  # `curl … | sh` → `sudo installer -pkg` — installs an unsigned .pkg
  # without complaint. Verified on a brand-new MacBook on 2026-08-23
  # ("The install was successful"). What notarisation actually buys is
  # the Finder double-click path, plus tamper-evidence — worth having,
  # not worth blocking every Linux and Windows release for.
  if [[ "${{ needs.validate-version.outputs.is_release }}" == "true" ]]; then
    echo "::warning::RELEASING AN UNSIGNED, UNNOTARISED .pkg. It installs fine via install.sh (curl sets no quarantine xattr) but Finder double-click will be refused, and the download has no tamper-evidence. Configure the six APPLE_* secrets to fix: scripts/signing/60-apple-setup.sh."
  else
    echo "::warning::Apple credentials absent -- the .pkg will be unsigned and unnotarised (artifacts-only run, so this is allowed)."
  fi
fi

echo "mode=$mode" >> "$GITHUB_OUTPUT"
echo "Apple signing mode: $mode"
```


### Archived step: Install system deps (original line 2437)

```text
brew install cmake libvpx pkg-config
```


### Archived step: Drop cached libvpx build artefacts (brew version drifts) (original line 2455)

```text
set -euo pipefail
echo "brew libvpx: $(brew --prefix libvpx 2>/dev/null || echo '(none)')"
rm -rfv target/aarch64-apple-darwin/release/build/*libvpx* \
        target/aarch64-apple-darwin/release/build/*vpx_sys* 2>/dev/null || true
echo "stale libvpx build artefacts cleared"
```


### Archived step: Fetch vendored FFmpeg 9.0.1 (macOS arm64 — VideoToolbox) (original line 2465)

```text
set -euo pipefail
# NOTE (FR-62 A2): NO patch drift gate here, deliberately. This
# macOS build is --disable-everything + the three *_videotoolbox
# encoders only, so libavcodec/nvenc.c (what 0001 patches) is never
# compiled in — the nvenc patch does not apply to what ships on a
# Mac. When 0002-videotoolbox-runtime-bitrate lands (FR-62 A3), wire
# vendor-ffmpeg-macos.yml to apply patches + emit MESHHARBOR-PATCHES.txt
# and add the Linux/Windows-twin gate below.
# Built once by vendor-ffmpeg-macos.yml and reused here, same
# prebuild-once model as the Linux lane. That workflow configures
# --disable-autodetect --disable-xlib --disable-libxcb, so this
# artifact carries NO Homebrew dependency — which is the whole
# reason ffmpeg-encoder can come back to this platform at all.
#
# It is also minimal (--disable-everything + the three
# *_videotoolbox encoders): 775 KB packed, ~1.8 MB of dylibs,
# against ~20 MB for the untrimmed tree that would have doubled
# the .pkg. FR-85 P4c added `-h264dec-aac` (the software h264
# decoder the recorder's editor needs and the aac encoder for its
# sound; 1,071,108 B packed, ~3.0 MB of dylibs); rollback = drop it.
mkdir -p /tmp/ffdl "$RUNNER_TEMP/meshharbor-ffmpeg"
gh release download vendored-ffmpeg-9.0.1 \
  --repo "${{ github.repository }}" \
  --pattern 'ffmpeg-9.0.1-macos-arm64-lgpl-shared-h264dec-aac.tar.xz' \
  --dir /tmp/ffdl --clobber
# NOTE: no --strip-components. The macOS tarball is packed as
# `tar cJf … lib include` from the install prefix, so lib/ and
# include/ are already at the root — unlike the Linux one, which
# has a wrapping directory and does strip 1.
tar xf /tmp/ffdl/ffmpeg-9.0.1-macos-arm64-lgpl-shared-h264dec-aac.tar.xz \
  -C "$RUNNER_TEMP/meshharbor-ffmpeg"
# BSD sed needs an explicit (empty) backup suffix; GNU `sed -i`
# would silently create files named after the next argument.
sed -i '' "s|^prefix=.*|prefix=$RUNNER_TEMP/meshharbor-ffmpeg|" \
  "$RUNNER_TEMP/meshharbor-ffmpeg"/lib/pkgconfig/*.pc
{
  echo "FFMPEG_DIR=$RUNNER_TEMP/meshharbor-ffmpeg"
  echo "PKG_CONFIG_PATH=$RUNNER_TEMP/meshharbor-ffmpeg/lib/pkgconfig"
} >> "$GITHUB_ENV"
echo "=== vendored dylibs ==="
ls -1 "$RUNNER_TEMP/meshharbor-ffmpeg/lib"/*.dylib | sed 's|.*/|    |'
# Fail here rather than at link time if the artifact is the old
# poisoned build — it is the cheapest place to catch it, and the
# failure mode it prevents is every Mac dying at launch.
if grep -rqa -E '/opt/homebrew|/usr/local/' "$RUNNER_TEMP/meshharbor-ffmpeg/lib"/*.dylib; then
  echo "::error::vendored FFmpeg carries Homebrew paths — re-run vendor-ffmpeg-macos.yml"
  exit 1
fi
echo "  clean (no Homebrew/usr-local references)"
```


### Archived step: Build agent (release, full + vp9-444 + vp9-444-bindgen + ffmpeg-encoder) (original line 2582)

```text
cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ssh-server,ffmpeg-encoder" --target aarch64-apple-darwin
```


### Archived step: Build the meshharbor CLI shim (original line 2590)

```text
cargo build -p meshharbor-cli-shim --release --target aarch64-apple-darwin
```


### Archived step: Wait for the desktop companion (built in parallel) (original line 2606)

```text
set -euo pipefail
for i in $(seq 1 180); do # 30 min at 10 s
  state=$(gh api "repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/jobs?filter=latest&per_page=100" \
    --jq '.jobs[] | select(.name == env.COMPANION_JOB) | "\(.status) \(.conclusion // "")"' | head -n1)
  case "$state" in
    "completed success")
      echo "companion ready (waited $(( (i - 1) * 10 )) s)"
      exit 0 ;;
    completed*)
      echo "::error::'$COMPANION_JOB' finished '${state#completed }', so there is no companion to package"
      exit 1 ;;
  esac
  sleep 10
done
echo "::error::'$COMPANION_JOB' did not finish within 30 min"
exit 1
```


### Archived step: Check the downloaded companion (original line 2633)

```text
set -euo pipefail
f=target/aarch64-apple-darwin/release/meshharbor-desktop
chmod +x "$f"
desc="$(file "$f")"
echo "$desc"
echo "$desc" | grep -q 'Mach-O 64-bit executable arm64' \
  || { echo "::error::the companion artifact is not an arm64 Mach-O executable"; exit 1; }
```


### Archived step: Import the stable self-signed signing identity (original line 2662)

```text
set -euo pipefail
if [ -z "${SELFSIGN_P12_BASE64:-}" ] || [ -z "${SELFSIGN_PASSWORD:-}" ]; then
  echo 'SIGN_ID=-' >> "$GITHUB_ENV"
  if [[ "${{ needs.validate-version.outputs.is_release }}" == "true" ]]; then
    echo "::warning::MACOS_SELFSIGN_* secrets absent — RELEASING WITH AD-HOC SIGNATURES. Every self-update of this build will WIPE the Mac's TCC grants (Screen Recording + Accessibility)."
  else
    echo "self-sign secrets absent (artifacts-only run) — using ad-hoc"
  fi
  exit 0
fi
KEYCHAIN=selfsign.keychain
KEYCHAIN_PASSWORD=$(openssl rand -hex 24)
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
echo "$SELFSIGN_P12_BASE64" | base64 -d > /tmp/selfsign.p12
security import /tmp/selfsign.p12 -k "$KEYCHAIN" -P "$SELFSIGN_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security
rm /tmp/selfsign.p12
security list-keychain -d user -s "$KEYCHAIN" login.keychain
security set-key-partition-list -S apple-tool:,apple: \
  -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
# A self-signed cert has NO trust settings, and both
# `find-identity -v -p codesigning` and codesign itself require the
# cert to pass codesigning TRUST evaluation — on a dev Mac the
# Keychain Assistant adds that trust invisibly when it mints the
# cert, in CI nobody does, so the rc.477 run imported the identity
# ("1 identity imported.") and then could not SEE it. Trust the
# committed public cert in the System keychain (runners have
# passwordless sudo); `-p codeSign` scopes the trust to exactly the
# policy we need.
sudo security add-trusted-cert -d -r trustRoot -p codeSign \
  -k /Library/Keychains/System.keychain \
  scripts/signing/macos/meshharbor-selfsign-cert.pem
# Identity presence is the gate: a p12 that imported but yields no
# VALID signing identity must fail HERE, not as a cryptic codesign
# error three steps later. Dump what the keychain does hold on
# failure so the next person is not diagnosing blind.
security find-identity -v -p codesigning "$KEYCHAIN" \
  | grep -q "MeshHarbor Self-Signed Code Signing" \
  || {
    echo "::error::imported p12 yields no VALID 'MeshHarbor Self-Signed Code Signing' identity"
    echo "--- all identities in $KEYCHAIN (unfiltered) ---"
    security find-identity "$KEYCHAIN" || true
    exit 1
  }
echo 'SIGN_ID=MeshHarbor Self-Signed Code Signing' >> "$GITHUB_ENV"
echo "stable signing identity imported"
```


### Archived step: Stage .app bundle (original line 2714)

```text
set -euo pipefail
# FR-46 P5b: the .app, its executable and CFBundleName now all carry the
# CURRENT name. CFBundleIdentifier stays `fans.itachi.meshharbor.agent` on purpose —
# it is not a retired name, it doubles as the launchd Label, and it is what
# TCC attributes the grants to, so changing it would widen the blast radius
# of a rename that already costs a re-approval at every Mac.
BIN=target/aarch64-apple-darwin/release/meshharbord
APP=stage/meshharbord.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/meshharbord"
# Bundle every non-system dylib the binary loads into the .app, so
# it is self-contained on a Mac that has never seen Homebrew.
#
# This is BY DEPENDENCY WALK, not by a hand-written list of libraries
# we expect. The hand-written version is what shipped rc.452 broken:
# it copied the FFmpeg dylibs (which someone remembered) and missed
# libvpx (which nobody did), and dyld aborted at launch on the first
# end-user Mac. A walk cannot miss one, and it keeps working when a
# future feature links something new.
#
# A brew dylib's install name is an ABSOLUTE path
# (/opt/homebrew/opt/<f>/lib/…), so an LC_RPATH alone cannot redirect
# it — each reference has to be rewritten to @rpath explicitly.
# Deps of deps are rewritten too: dyld resolves the whole graph at
# launch, so one unrewritten leaf is still a crash.
FW="$APP/Contents/Frameworks"
mkdir -p "$FW"
# Where an `@rpath/…` dependency can actually be found. A dylib built
# with `--install-name-dir=@rpath` (the vendored FFmpeg) advertises
# itself as `@rpath/libavcodec.63.dylib`, so `otool -L` on our binary
# reports that and NOT a filesystem path.
#
# ⚠️ Treating `@…` as "already handled" is wrong and was caught by the
# self-containment check below on the first VideoToolbox build:
# libvpx came from Homebrew with an absolute install name and got
# bundled, while the four FFmpeg dylibs were skipped as already-@rpath
# and NOTHING copied them — the staged binary then died
# `Library not loaded: @rpath/libavcodec.63.dylib`. `@rpath` says how
# to LOOK for a library, never that it is present.
RPATH_SEARCH="${FFMPEG_DIR:+$FFMPEG_DIR/lib}"
bundle_deps() {
  local target="$1" dep base src
  # otool -L: line 1 is the file itself; field 1 of the rest is the path.
  #
  # Fed by process substitution, NOT a pipe: a piped `while` runs in a
  # SUBSHELL, so the `exit 1` below would kill only that subshell and
  # the step would sail on green. Same reason the /opt gate further
  # down is written this way.
  while read -r dep; do
    case "$dep" in
      /usr/lib/*|/System/*) continue ;;     # OS-provided
      @executable_path/*|@loader_path/*) continue ;;  # already bundle-relative
    esac
    base="$(basename "$dep")"
    case "$dep" in
      @rpath/*)
        # Resolve against the trees we know we linked against. If it
        # is already in Frameworks the reference is fine as-is.
        [ -f "$FW/$base" ] && continue
        src=""
        for d in $RPATH_SEARCH; do
          [ -f "$d/$base" ] && { src="$d/$base"; break; }
        done
        if [ -z "$src" ]; then
          echo "::error::@rpath dep $dep is not in Frameworks and not in \$RPATH_SEARCH ($RPATH_SEARCH)"
          exit 1
        fi
        ;;
      *) src="$dep" ;;
    esac
    if [ ! -f "$FW/$base" ]; then           # on-disk presence = the "seen" set
      echo "    bundling $src"
      cp -L "$src" "$FW/$base"             # -L: brew's opt path is a symlink into the Cellar
      chmod u+w "$FW/$base"
      install_name_tool -id "@rpath/$base" "$FW/$base"
      bundle_deps "$FW/$base"               # recurse into the copy's own deps
    fi
    # An already-@rpath reference needs no rewrite; an absolute one does.
    case "$dep" in
      @rpath/*) ;;
      *) install_name_tool -change "$dep" "@rpath/$base" "$target" ;;
    esac
  done < <(otool -L "$target" | tail -n +2 | awk '{print $1}')
}
echo "=== bundling non-system dylibs ==="
install_name_tool -add_rpath "@executable_path/../Frameworks" "$APP/Contents/MacOS/meshharbord"
bundle_deps "$APP/Contents/MacOS/meshharbord"
ls -1 "$FW" 2>/dev/null || echo "    (none needed)"

# install_name_tool invalidates the linker's ad-hoc signature, and an
# arm64 Mach-O with a broken signature is killed by the kernel at
# exec. Xcode's tool re-signs automatically, but do it explicitly so
# the artifact does not depend on that behaviour. In `full` mode the
# codesign steps below replace these with the Developer ID identity.
# $SIGN_ID is the STABLE self-signed identity (or "-" ad-hoc
# fallback) — see the import step for why stability matters (TCC).
find "$APP" -type f \( -name '*.dylib' -o -name 'meshharbord' \) \
  -exec codesign --force --timestamp=none --sign "$SIGN_ID" {} \;

echo "=== GATE: no Mach-O in the .app may reference a non-system path ==="
# The `--version` run below is NOT sufficient on its own and never
# was: the runner has Homebrew, so a binary that depends on it starts
# here and dies on the user's machine. That is precisely how rc.452
# shipped. This scan reads the load commands themselves, so it is
# independent of what happens to be installed on the builder.
bad=0
# Process substitution, NOT a pipe: a `while` on the right of a pipe
# runs in a subshell and `bad` would be lost on the way out.
while IFS= read -r f; do
  refs="$(otool -L "$f" 2>/dev/null | tail -n +2 | awk '{print $1}' \
          | grep -E '^/(opt|usr/local)/' || true)"
  if [ -n "$refs" ]; then
    echo "::error::$f loads paths absent from a clean Mac:"
    echo "$refs" | sed 's/^/    /'
    bad=1
  fi
done < <(find "$APP" -type f)
[ "$bad" -eq 0 ] || exit 1
echo "  clean — every load command is /usr/lib, /System or @rpath."

echo "=== self-containment check: run it with Homebrew HIDDEN ==="
# macos-15 is arm64, so the staged binary runs here. Hiding the brew
# prefix for the duration makes this an honest end-user simulation
# rather than a check the builder's own environment can satisfy.
# Restore BEFORE acting on the result, so a failure cannot leave the
# runner without its Homebrew tree.
hidden=0
if [ -d /opt/homebrew/opt ]; then
  mv /opt/homebrew/opt /opt/homebrew/opt.hidden
  hidden=1
fi
rc=0
"$APP/Contents/MacOS/meshharbord" --version || rc=$?
[ "$hidden" -eq 1 ] && mv /opt/homebrew/opt.hidden /opt/homebrew/opt
if [ "$rc" -ne 0 ]; then
  echo "::error::the staged binary does not start without Homebrew (exit $rc) — it is not self-contained"
  exit 1
fi
cp agents/meshharbord/packaging/macos/fans.itachi.meshharbor.agent.plist "$APP/Contents/Resources/"
# The privileged half's plist rides along in Resources; the
# postinstall only installs it into /Library/LaunchDaemons when the
# operator has opted in. Staged unconditionally so enabling the
# daemon never requires a different package.
cp agents/meshharbord/packaging/macos/fans.itachi.meshharbor.daemon.plist "$APP/Contents/Resources/"
# The companion's LaunchAgent rides here too — the postinstall reads
# every plist it installs out of this one directory.
cp agents/meshharbord/packaging/macos/fans.itachi.meshharbor.desktop.plist "$APP/Contents/Resources/"
# The update half (root LaunchDaemon, DEFAULT ON, opt-out marker
# /etc/meshharbor/disable-auto-update). Owns check+download+
# install so no agent process ever execs its own replacement.
cp agents/meshharbord/packaging/macos/fans.itachi.meshharbor.update.plist "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>          <string>meshharbord</string>
    <key>CFBundleIdentifier</key>          <string>fans.itachi.meshharbor.agent</string>
    <key>CFBundleName</key>                <string>MeshHarbor Daemon</string>
    <key>CFBundleShortVersionString</key>  <string>${VERSION}</string>
    <key>CFBundleVersion</key>             <string>${VERSION}</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>LSMinimumSystemVersion</key>      <string>${MACOS_FLOOR}</string>
    <key>LSUIElement</key>                 <true/>
    <key>NSPrincipalClass</key>            <string>NSApplication</string>
    <key>NSScreenCaptureUsageDescription</key>
        <string>MeshHarbor Daemon captures the screen to stream it to an authorised remote controller.</string>
    <key>NSAppleEventsUsageDescription</key>
        <string>MeshHarbor Daemon injects input events on behalf of an authorised remote controller.</string>
</dict>
</plist>
PLIST

# SEAL THE BUNDLE LAST — after every file is in place.
#
# The per-file signing above is what lets the binary exec for the
# self-containment check, but signing a bundle's MAIN EXECUTABLE makes
# codesign seal the whole BUNDLE: it writes
# Contents/_CodeSignature/CodeResources covering the files present at
# that moment. Both plists and Info.plist are written afterwards, so
# that seal was false the instant it was created.
#
# rc.453 and rc.454 shipped exactly that; rc.452, which predates the
# ad-hoc signing, carries no _CodeSignature at all and installed
# cleanly on a real Mac. Re-sealing after the last write is the fix,
# and it is what the Developer ID path below already does by running
# last.
codesign --force --timestamp=none --sign "$SIGN_ID" "$APP"
# A seal that does not match its contents is exactly the bug above, so
# assert rather than assume. `--strict` makes codesign check the
# sealed resources instead of only the signature's own integrity.
codesign --verify --strict --verbose=2 "$APP" || {
  echo "::error::the .app's signature does not match its contents"
  exit 1
}
# When the stable identity is in play, assert it actually SIGNED —
# an env var lost between steps would silently ship ad-hoc and
# re-introduce the per-update TCC wipe.
if [ "$SIGN_ID" != "-" ]; then
  # ⚠️ Authority= lines only appear at --verbose=2 and above; plain
  # `-dv` (verbosity 1) NEVER prints them, so the rc.478 assert
  # failed on a perfectly-signed bundle. Same lesson as the smoke's
  # own history: an assert that can't distinguish pass from fail
  # must dump what it actually saw.
  codesign -d --verbose=2 "$APP" 2>&1 | grep -q "Authority=MeshHarbor Self-Signed Code Signing" || {
    echo "::error::bundle is not signed by the stable identity (Authority missing)"
    echo "--- codesign -d --verbose=2 output ---"
    codesign -d --verbose=2 "$APP" 2>&1 || true
    exit 1
  }
  echo "  sealed with the stable identity"
fi
```


### Archived step: Stage the desktop companion (.app) (original line 2930)

```text
set -euo pipefail
# A Tauri app must be a real bundle on macOS — it owns a menu-bar item
# and a WKWebView, and both want bundle identity (and LSUIElement, to
# stay out of the Dock). Hand-staged rather than built with
# `cargo tauri build` for the same reason the Windows lane uses plain
# `cargo build`: no Tauri toolchain on the runner, and the frontend is
# already embedded via `custom-protocol`.
DESK=stage/MeshHarbor.app
mkdir -p "$DESK/Contents/MacOS" "$DESK/Contents/Resources"
cp target/aarch64-apple-darwin/release/meshharbor-desktop "$DESK/Contents/MacOS/meshharbor-desktop"
cp agents/meshharbor-desktop/icons/icon.png "$DESK/Contents/Resources/icon.png"
cat > "$DESK/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>          <string>meshharbor-desktop</string>
    <key>CFBundleIdentifier</key>          <string>fans.itachi.meshharbor.agent-tray</string>
    <key>CFBundleName</key>                <string>MeshHarbor</string>
    <key>CFBundleShortVersionString</key>  <string>${VERSION}</string>
    <key>CFBundleVersion</key>             <string>${VERSION}</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>CFBundleIconFile</key>            <string>icon.png</string>
    <key>LSMinimumSystemVersion</key>      <string>${MACOS_FLOOR}</string>
    <!-- Menu-bar only: no Dock tile, no app-switcher entry. -->
    <key>LSUIElement</key>                 <true/>
    <key>NSHighResolutionCapable</key>     <true/>
</dict>
</plist>
PLIST

# Seal AFTER every file is in place — same ordering rule as the agent
# bundle, where signing first produced a _CodeSignature that no longer
# matched its contents. Same stable identity as the agent: the
# companion holds no TCC grants today, but a future one (e.g.
# notifications) should not start from the wipe-per-update state.
codesign --force --timestamp=none --sign "$SIGN_ID" "$DESK"
codesign --verify --strict "$DESK" || {
  echo "::error::the companion .app's signature does not match its contents"
  exit 1
}
# It links only system frameworks; assert that rather than assume it,
# since the agent bundle taught us what an un-checked dylib costs.
bad="$(otool -L "$DESK/Contents/MacOS/meshharbor-desktop" | tail -n +2 | awk '{print $1}' \
       | grep -E '^/(opt|usr/local)/' || true)"
[ -z "$bad" ] || { echo "::error::companion loads non-system paths:"; echo "$bad"; exit 1; }
# dyld/exec smoke, HARD-BOUNDED: `|| true` guards the exit code,
# not a hang — once #659 made the companion actually START, this
# probe launched a Tauri menu-bar event loop that never exits and
# pinned the job until timeout (run 32738472108: 20+ min stuck
# here; previously the binary failed fast, so the line "worked").
# Background + kill keeps the probe's only real value (a dyld
# crash still surfaces in the log) without trusting the binary
# to ever return. macOS runners lack GNU `timeout` natively, so
# do it by hand.
"$DESK/Contents/MacOS/meshharbor-desktop" --version 2>/dev/null &
probe=$!
sleep 5
kill -9 "$probe" 2>/dev/null || true
wait "$probe" 2>/dev/null || true
echo "  companion staged: $(du -h "$DESK/Contents/MacOS/meshharbor-desktop" | cut -f1)"
```


### Archived step: Import signing certs (original line 2995)

```text
set -euo pipefail
KEYCHAIN=build.keychain
KEYCHAIN_PASSWORD=$(openssl rand -hex 24)

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

echo "$APP_P12_BASE64" | base64 -d > /tmp/app.p12
security import /tmp/app.p12 -k "$KEYCHAIN" -P "$CERT_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security

echo "$INSTALLER_P12_BASE64" | base64 -d > /tmp/installer.p12
security import /tmp/installer.p12 -k "$KEYCHAIN" -P "$CERT_PASSWORD" \
  -T /usr/bin/productbuild -T /usr/bin/security

security list-keychain -d user -s "$KEYCHAIN" login.keychain
security set-key-partition-list -S apple-tool:,apple: \
  -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

rm /tmp/app.p12 /tmp/installer.p12

# Print identities (harmless — just the CN, not the cert itself)
security find-identity -v -p codesigning "$KEYCHAIN"
```


### Archived step: Codesign binary (original line 3023)

```text
set -euo pipefail
# Sign the bundled dylibs FIRST (inside-out) — the hardened runtime +
# notarisation reject unsigned nested code.
#
# `--force` throughout: everything here already carries a signature.
# arm64 Mach-Os are ad-hoc signed by the linker, and the staging step
# re-signs whatever install_name_tool rewrote. Without --force,
# codesign refuses with "is already signed" — and since the Apple
# secrets have never been configured, this whole branch has never
# executed, so nothing would have caught it but a release.
find stage/meshharbord.app/Contents/Frameworks -type f -name '*.dylib' -print0 \
  | while IFS= read -r -d '' dylib; do
      codesign --force --sign "Developer ID Application" --options runtime --timestamp "$dylib"
    done
codesign --force --sign "Developer ID Application" \
         --options runtime --timestamp \
         --entitlements agents/meshharbord/packaging/macos/entitlements.plist \
         "stage/meshharbord.app/Contents/MacOS/meshharbord"

codesign --force --sign "Developer ID Application" \
         --options runtime --timestamp \
         "stage/meshharbord.app"

# The CLI shim ships in the same .pkg, outside the bundle. Sign it
# HERE: nothing may `cargo build` after this point (a relink strips
# signatures), and pkgbuild harvests it in the very next step.
codesign --force --sign "Developer ID Application" \
         --options runtime --timestamp \
         "target/aarch64-apple-darwin/release/meshharbor-shim"

# The desktop companion ships in the SAME .pkg (payload/Applications),
# and it was sealed earlier with $SIGN_ID -- the stable SELF-SIGNED
# identity, `--timestamp=none`, no hardened runtime. That is correct
# for an unsigned-fallback build and FATAL here: Apple's notary
# service refuses a nested bundle on any one of those three counts,
# and this payload tripped all three. Re-seal it with the real
# identity, inside-out, BEFORE `cp -R stage/MeshHarbor.app` runs.
#
# Field evidence (2026-09-08, the first run that ever had Apple
# credentials): meshharbord.app and meshharbor-shim were correctly
# Developer-ID-signed and the .pkg itself carried "Developer ID
# Installer: G ROX EOOD", yet notarisation still returned
# `status: Invalid` -- because MeshHarbor.app inside it was self-signed.
find "stage/MeshHarbor.app/Contents" -type f -name '*.dylib' -print0 2>/dev/null \
  | while IFS= read -r -d '' nested; do
      codesign --force --sign "Developer ID Application" \
               --options runtime --timestamp "$nested"
    done
codesign --force --sign "Developer ID Application" \
         --options runtime --timestamp \
         "stage/MeshHarbor.app"
codesign --verify --strict "stage/MeshHarbor.app"
```


### Archived step: Check the bundle runs on its declared minimum macOS (original line 3085)

```text
set -euo pipefail
# LC_BUILD_VERSION's minos, or the legacy LC_VERSION_MIN_MACOSX.
minos() { otool -l "$1" | awk '/LC_BUILD_VERSION|LC_VERSION_MIN_MACOSX/ {b = 1} b && ($1 == "minos" || $1 == "version") {print $2; exit}'; }
# $1 <= $2, as dotted versions.
le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)" = "$2" ]; }
fail=0; n=0
while IFS= read -r -d '' f; do
  case "$(file -b "$f")" in *Mach-O*) ;; *) continue ;; esac
  n=$((n + 1))
  m=$(minos "$f")
  if [ -z "$m" ]; then
    echo "::error::no minimum macOS recorded in $f"; fail=1
  elif le "$m" "$MACOS_FLOOR"; then
    echo "  ok   macOS $m  $f"
  else
    echo "::error::$f requires macOS $m, above this .pkg's floor of $MACOS_FLOOR"; fail=1
  fi
done < <(find stage/meshharbord.app stage/MeshHarbor.app \
              target/aarch64-apple-darwin/release/meshharbor-shim -type f -print0)
[ "$n" -gt 0 ] || { echo "::error::found no Mach-O files to check"; exit 1; }
for p in stage/meshharbord.app/Contents/Info.plist stage/MeshHarbor.app/Contents/Info.plist; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$p")
  [ "$v" = "$MACOS_FLOOR" ] || { echo "::error::$p declares LSMinimumSystemVersion $v, not $MACOS_FLOOR"; fail=1; }
done
echo "checked $n Mach-O files against macOS $MACOS_FLOOR"
exit "$fail"
```


### Archived step: Build component + product pkg (original line 3116)

```text
set -euo pipefail
mkdir -p payload/Applications payload/Library/MeshHarbor payload/usr/local/bin scripts dist
# The DAEMON bundle goes to /Library/MeshHarbor, NOT /Applications.
#
# It is a background service with no window and nothing to launch —
# putting it in /Applications gave the user two MeshHarbor icons, one of
# which does nothing when double-clicked, and made the internal
# internal daemon name look like a stale leftover next to `MeshHarbor`.
# /Library/<Vendor> is the conventional home for a helper the user
# never opens, and Finder and Launchpad do not surface it.
#
# Still a BUNDLE, not a bare binary: TCC attributes Screen Recording
# and Accessibility to a bundle identity, and Info.plist carries the
# two usage descriptions macOS shows in the permission prompt.
#
# ⚠️ The path is part of the TCC identity, so this move costs every
# existing Mac one re-grant. Unavoidable, and cheapest now while the
# platform has almost no installs.
cp -R stage/meshharbord.app payload/Library/MeshHarbor/
# The CLI. Until rc.454 the macOS payload was the .app and NOTHING
# else — no `mh` on PATH, so `mh peers` was impossible on a
# Mac even though the daemon carries the whole command surface. Same
# ~150 KB shim the .deb and the MSI install; it re-execs
# `<daemon> cli <args>`, resolving the bundle path on macOS because
# the two binaries cannot be siblings here.
cp target/aarch64-apple-darwin/release/meshharbor-shim payload/usr/local/bin/mh
chmod 755 payload/usr/local/bin/mh
# The menu-bar companion, and its LaunchAgent (installed by the
# postinstall alongside the agent's).
cp -R stage/MeshHarbor.app payload/Applications/
# `meshharbord` on PATH for command-surface parity with Linux and
# Windows. A symlink, not a copy: the daemon binary lives inside the
# bundle (its name is CFBundleExecutable and every launchd plist and
# TCC grant is keyed to that path), so this is a convenience entry
# point for `meshharbord enroll` / `--version`, not a second install.
ln -s /Library/MeshHarbor/meshharbord.app/Contents/MacOS/meshharbord \
  payload/usr/local/bin/meshharbord
cp agents/meshharbord/packaging/macos/postinstall scripts/postinstall
chmod 755 scripts/postinstall

# Turn OFF bundle relocation. This is not a nicety.
#
# `pkgbuild --root` infers the .app as a BUNDLE COMPONENT and marks it
# relocatable by default. PackageKit then asks LaunchServices where a
# bundle with this identifier already lives and installs THERE,
# ignoring the payload path. Measured on a CI runner:
#
#   PackageKit: Applications/meshharbord.app relocated to
#               Users/runner/work/.../payload/Applications/meshharbord.app
#
# …i.e. it installed into the staging directory it had just been built
# from. On a user's Mac the same rule redirects the install to any
# indexed copy — an old one in ~/Downloads, a previous install in a
# different folder — while both launchd plists and the postinstall go
# on naming /Applications, so the install "succeeds" into a path
# nothing else references.
#
# Everything here installs to a fixed absolute path, so relocation is
# never wanted.
pkgbuild --analyze --root payload component.plist
i=0
while /usr/libexec/PlistBuddy -c "Print :$i:BundleIsRelocatable" component.plist >/dev/null 2>&1; do
  /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" component.plist
  i=$((i + 1))
done
[ "$i" -gt 0 ] || { echo "::error::pkgbuild --analyze found no bundle component to pin"; exit 1; }
echo "pinned $i bundle component(s) to their payload path"
plutil -p component.plist

pkgbuild \
  --root payload \
  --component-plist component.plist \
  --scripts scripts \
  --identifier fans.itachi.meshharbor.agent \
  --version "$VERSION" \
  --install-location / \
  component.pkg

# Suffix-free name in both branches: signedness is VERIFIED by the
# step below, not encoded in a filename. install.sh's
# `aarch64-apple-darwin[^"]*\.pkg` regex matches either way, so
# already-published `-unsigned` releases keep resolving too.
artifact="dist/meshharbord-$VERSION-aarch64-apple-darwin.pkg"

# The product archive carries an installer-enforced minimum macOS
# (MACOS_FLOOR): a Mac below it refuses the update and keeps running
# what it has. See the script's header.
if [[ "${{ steps.apple.outputs.mode }}" == "full" ]]; then
  bash scripts/macos-productbuild-gated.sh component.pkg "$artifact" "$MACOS_FLOOR" "Developer ID Installer"
else
  bash scripts/macos-productbuild-gated.sh component.pkg "$artifact" "$MACOS_FLOOR"
fi

echo "artifact=$artifact" >> "$GITHUB_OUTPUT"
```


### Archived step: Notarise (original line 3214)

```text
set -euo pipefail
mkdir -p ~/.appstoreconnect/private_keys
KEY="$HOME/.appstoreconnect/private_keys/AuthKey_${APPLE_API_KEY_ID}.p8"
echo "$APPLE_API_KEY_P8_BASE64" | base64 -d > "$KEY"

# Capture the submission id, because `--wait` prints "status: Invalid"
# and NOT ONE WORD about why. The per-file reasons live only in the
# notarisation log, which is reachable solely by that id -- so without
# this, a refusal is unfalsifiable: you know Apple said no, and cannot
# tell which of a dozen causes it was. Measured 2026-09-08: the first
# run that ever had credentials failed here, and diagnosing it needed
# the workflow source rather than the log, which is the wrong way round.
set +e
# `--timeout` is NOT optional, and the value is load-bearing in BOTH
# directions.
#
# Without it, `--wait` polls until something else kills it -- and that
# something is the JOB timeout, which takes the runner down mid-poll:
# no verdict, no `notarytool log`, and the whole diagnostic below
# unreachable in exactly the case you most want it.
#
# Set it too LOW and it kills legitimate work. Measured 2026-09-08,
# the first successful notarisation this project ever had: Apple's
# queue took **71 minutes** to return `Accepted`, on a run whose
# signing steps had all passed and with no incident on Apple's status
# page. The job finished in 84 of its 90 allotted minutes -- six to
# spare. An earlier draft of this fix used `--timeout 25m` and would
# have aborted that run as a failure.
#
# So: job budget 180m (was 90 -- a 6-minute margin is not a margin),
# notary bound 120m below it. A genuinely stuck submission now fails
# with a REASON and ~60m of budget left to report it, while a merely
# slow one still completes. For contrast, a structurally-invalid
# package is refused in ~25 SECONDS -- fast rejection, slow
# acceptance, so a long wait is evidence FOR the payload, not against.
out=$(xcrun notarytool submit "${{ steps.pkg.outputs.artifact }}" \
        --key "$KEY" \
        --key-id "$APPLE_API_KEY_ID" \
        --issuer "$APPLE_API_ISSUER_ID" \
        --timeout 120m \
        --wait 2>&1)
rc=$?
set -e
printf '%s\n' "$out"

if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -q 'status: Accepted'; then
  sub=$(printf '%s\n' "$out" | awk '/^ *id: /{print $2; exit}')
  # Do not call this "refused": a timeout and a rejection both land
  # here and they need different responses -- re-submit vs fix the
  # payload. Say which, and always print the id so the submission can
  # be re-queried by hand after the runner is gone.
  if printf '%s\n' "$out" | grep -qi 'timed out\|timeout'; then
    echo "::error::notarisation did not return a verdict within the timeout (submission ${sub:-unknown}) -- Apple's queue, not necessarily the payload. Re-query: xcrun notarytool info ${sub:-<id>}"
  else
    echo "::error::notarisation did not reach Accepted (submission ${sub:-unknown}) -- per-file reasons follow"
  fi
  if [ -n "$sub" ]; then
    xcrun notarytool log "$sub" \
      --key "$KEY" \
      --key-id "$APPLE_API_KEY_ID" \
      --issuer "$APPLE_API_ISSUER_ID" /dev/stdout || true
  fi
  exit 1
fi

# Retried: since 2026-10-12 the ticket fetch drops its connection on
# GitHub's macOS runners after `Accepted` (exit 68; the script says why).
bash "$GITHUB_WORKSPACE/scripts/signing/stapler-retry.sh" staple "${{ steps.pkg.outputs.artifact }}"
```


### Archived step: Verify signature + notarisation (original line 3290)

```text
set -euo pipefail
PKG="${{ steps.pkg.outputs.artifact }}"

echo "=== codesign (app bundle, strict) ==="
codesign --verify --strict --verbose=2 stage/meshharbord.app

echo "=== hardened runtime ==="
codesign -d --verbose=2 stage/meshharbord.app 2>&1 | grep -q 'flags=.*runtime' \
  || { echo "::error::hardened runtime is NOT enabled on the app bundle -- notarisation would reject it"; exit 1; }

echo "=== pkg signature ==="
pkgutil --check-signature "$PKG"

echo "=== stapled notarisation ticket ==="
bash "$GITHUB_WORKSPACE/scripts/signing/stapler-retry.sh" validate "$PKG"

echo "=== Gatekeeper (authoritative end-to-end check) ==="
out="$(spctl -a -vvv -t install "$PKG" 2>&1 || true)"
echo "$out"
echo "$out" | grep -q 'source=Notarized Developer ID' \
  || { echo "::error::spctl did not report 'source=Notarized Developer ID'. The .pkg would be refused on end-user Macs."; exit 1; }
```


### Archived step: Warn on unsigned build (original line 3315)

```text
echo "::warning::Apple signing credentials absent — the .pkg is unsigned and unnotarised, and Gatekeeper will block it on every end-user Mac. Artifacts-only run, so not fatal."
```


### Archived step: SHA256 checksum (original line 3318)

```text
shasum -a 256 "${{ steps.pkg.outputs.artifact }}" > "${{ steps.pkg.outputs.artifact }}.sha256"
```


### Archived step: Cleanup keychain (original line 3322)

```text
security delete-keychain build.keychain || true
```


### Archived step: Flatten artifact tree (original line 3372)

```text
mkdir -p release
# rc.18: include `.exe` so the desktop companion EXE makes
# the GitHub Release alongside the agent MSI/.pkg/.deb.
# `windows-msi` carries the two agent MSIs; `windows-companions`
# carries the desktop EXE; flatten is extension-based
# so both artifact dirs (+ all .sha256 files) land unchanged.
# `.tar.gz` is the universal Linux installer (docs/linux-self-update.md);
# it must be listed here or the artifact is silently dropped from the
# Release and every non-Debian host keeps skipping its updates.
# `.rpm` is the companion's for those hosts (FR-93 P6d), and the same
# silent drop applies to it.
find dist -type f \( -name '*.msi' -o -name '*.pkg' -o -name '*.deb' -o -name '*.rpm' -o -name '*.exe' -o -name '*.tar.gz' -o -name '*.sha256' \) \
  -exec mv {} release/ \;
ls -la release/
```


### Archived step: GPG-sign release artifacts (original line 3412)

```text
set -euo pipefail
if [ -z "${GPG_PRIVATE_KEY:-}" ]; then
  if [ "${{ github.ref_type }}" = "tag" ]; then
    echo "::error::GPG_PRIVATE_KEY is not configured, but this is a release tag."
    echo "::error::Publishing without .asc sidecars would freeze every Linux/macOS"
    echo "::error::agent: updater.rs requires a verifying signature since rc.476."
    exit 1
  fi
  echo "::notice::GPG_PRIVATE_KEY not configured -- publishing without .asc signatures (not a tag)."
  exit 0
fi
echo "$GPG_PRIVATE_KEY" | gpg --batch --import
for f in release/*; do
  case "$f" in *.asc|*.sha256) continue ;; esac
  gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" \
      --armor --detach-sign "$f"
  echo "signed: $f"
done
# Republish the public key alongside the assets so verification
# never depends on a checkout of this repo.
gpg --batch --armor --export > release/meshharbor-release-pubkey.asc

# Assert the loop actually produced sidecars. `set -e` covers a gpg
# that FAILS, but not the case that matters here — a `release/` whose
# installers arrived under an unexpected name, or a glob that matched
# nothing, leaves the step green with zero signatures and the freeze
# lands on the fleet instead. Count what the updater will look for.
missing=0
for f in release/*.deb release/*.rpm release/*.pkg release/*.msi; do
  [ -e "$f" ] || continue
  if [ ! -e "$f.asc" ]; then
    echo "::error::no signature produced for $f"
    missing=$((missing + 1))
  fi
done
signed=$(ls release/*.asc 2>/dev/null | grep -vc 'meshharbor-release-pubkey' || true)
echo "signed $signed asset(s); $missing installer(s) unsigned"
if [ "$missing" -gt 0 ] || [ "$signed" -eq 0 ]; then
  echo "::error::refusing to publish a release the fleet would refuse to install."
  exit 1
fi
```


### Archived step: File or update the alert issue (original line 3524)

```text
set -euo pipefail
run_url="${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
existing=$(gh issue list --repo "${{ github.repository }}" --state open \
  --search 'in:title "Seed rehearsal failed"' --limit 1 --json number --jq '.[0].number // empty')

if [ -n "$existing" ]; then
  echo "reusing open alert #$existing"
  gh issue comment "$existing" --repo "${{ github.repository }}" \
    --body "$(printf 'Rehearsal failed again on %s: %s\n\nStill unresolved — the caches remain unrefreshed. This issue closes automatically when a rehearsal succeeds.\n' "$(date -u +%F)" "$run_url")"
else
  gh issue create --repo "${{ github.repository }}" \
    --title "Seed rehearsal failed — release-lane caches NOT refreshed ($(date -u +%F))" \
    --body "$(printf 'The artifacts-only release-agent rehearsal (weekly cron or seed-release-caches.yml dispatch) failed: %s\n\nUntil a rehearsal succeeds on master, agent tag builds run with cold cargo caches (~+14 min on the Windows MSI job). cache-on-failure means partial seeds may still have been saved, but the failure itself needs fixing.\n\nThis issue is reused by later failures and CLOSED automatically by the next successful rehearsal, so an open one always means "currently broken".\n\nRe-run after fixing:\n\n    gh workflow run release-agent.yml --ref master -f version=<workspace version> -f publish_release=false\n' "$run_url")"
fi
```


### Archived step: Close any open seed-rehearsal alert (original line 3576)

```text
set -euo pipefail
run_url="${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
# Every open alert, not just the newest: the pre-dedup ones accumulated
# and a single-issue close would leave the rest standing forever.
nums=$(gh issue list --repo "${{ github.repository }}" --state open \
  --search 'in:title "Seed rehearsal failed"' --limit 50 --json number --jq '.[].number')
if [ -z "$nums" ]; then
  echo "no open seed alert — nothing to close"
  exit 0
fi
for n in $nums; do
  echo "closing #$n"
  gh issue close "$n" --repo "${{ github.repository }}" --reason completed \
    --comment "$(printf 'Rehearsal succeeded on %s: %s\n\nThe release-lane caches are refreshed, so the condition this issue reports no longer holds. Closed automatically; it reopens as a new issue if a later rehearsal fails.\n' "$(date -u +%F)" "$run_url")"
done
```


### Archived step: Dispatch artifacts-only rehearsal (original line 3623)

```text
set -euo pipefail
# Read the version from MASTER (not the tag) — if another bump
# already landed, the rehearsal should build that state; if the
# version races mid-dispatch, validate-version fails loudly in
# ~30 s and the next release's reseed (or the cron) covers it.
version=$(awk '
  /^\[workspace\.package\]/ {in_section=1; next}
  /^\[/ {in_section=0}
  in_section && /^version[[:space:]]*=/ {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)
echo "Dispatching post-release seed rehearsal for ${version}"
gh workflow run release-agent.yml --ref master \
  -f version="${version}" -f publish_release=false
```


### Archived step: POST /api/releases/refresh (original line 3673)

```text
set -uo pipefail
if [ -z "${TOKEN}" ]; then
  echo "::notice::MESHHARBOR_RELEASE_REFRESH_TOKEN unset (fork?); skipping cache refresh"
  exit 0
fi
for attempt in 1 2 3; do
  body=$(curl -sS -m 90 -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://meshharbor.itachi.fans/api/releases/refresh?expect_tag=${TAG}")
  if [ "$(jq -r '.all_ok' <<<"$body" 2>/dev/null)" = "true" ]; then
    jq . <<<"$body"
    echo "Release cache refreshed on every live pod for ${TAG}"
    exit 0
  fi
  echo "attempt ${attempt}: ${body:-<no response>}"
  sleep 10
done
echo "::warning::release cache refresh did not confirm on every pod for ${TAG}; the cache TTL will heal it within 15 min"
```


### Archived step: Guard — the daemon .deb still wins the pre-0.4.16 picker (original line 3711)

```text
set -uo pipefail
feed=$(curl -sS -m 60 https://meshharbor.itachi.fans/api/agent/latest-release) || {
  echo "::warning::could not read the release feed; ordering unverified"; exit 0; }
for arch in x86_64 aarch64; do
  # `endswith`/`contains`, not a regex — the picker being replayed
  # does exactly that, and it keeps backslashes out of a shell string
  # inside a YAML block scalar (three quoting layers, one of which
  # silently ate the escape the first time this was written).
  first=$(jq -r --arg a "$arch" '
    [ .[0].assets[]?.name
      | select(endswith(".deb"))
      | select(contains($a)) ] | first // ""' <<<"$feed")
  echo "$arch -> ${first:-<no .deb>}"
  # FR-46: match the COMPANION, not an allowlist of daemon prefixes. The
  # old form (`""|meshharbor-agent-*`) hard-coded the daemon asset name, so
  # renaming that asset silently turned this guard into a permanent
  # warning — a stale allowlist that fires on the correct state. What
  # `order_assets_daemon_first` actually asserts server-side is a
  # `meshharbor-desktop-` DENYLIST, so replay exactly that and the guard
  # survives any future daemon rename.
  case "$first" in
    meshharbor-desktop-*) echo "::warning::a pre-0.4.16 $arch agent would install '$first' as its daemon update — the companion must sort AFTER the daemon in /api/agent/latest-release (agent_release::order_assets_daemon_first)" ;;
    *) ;;
  esac
done
```


### Archived step: Tag setup-v<V> at the released commit and dispatch release-setup.yml (original line 3786)

```text
set -euo pipefail
setup_tag="setup-v${VERSION}"
# The commit the agent release was BUILT from, read from the
# checkout rather than GITHUB_SHA: on an ANNOTATED tag push
# GITHUB_SHA is the tag object, not the commit (agent-v0.4.102 was
# annotated, 0.4.101 was not — both must produce a commit here).
commit=$(git rev-parse 'HEAD^{commit}')
echo "agent release ${AGENT_TAG} built from ${commit} (GITHUB_SHA=${GITHUB_SHA})"

refused=0
recover() {
  if [ "$refused" -eq 1 ]; then return; fi
  echo "::error::${setup_tag} was NOT released in lockstep with ${AGENT_TAG} — /api/setup serves the previous wizard until one of these runs:"
  echo "::error::  gh workflow run release-setup.yml --ref ${setup_tag} -f version=${VERSION} -f publish_release=true    # once ${setup_tag} exists at ${commit}"
  echo "::error::  git push origin ${commit}:refs/tags/${setup_tag}    # a tag pushed with a HUMAN token triggers release-setup.yml by itself"
}
trap 'rc=$?; [ "$rc" -eq 0 ] || recover' EXIT

# Idempotent tag: reuse it at the same commit, refuse it at another.
if git fetch --quiet origin "refs/tags/${setup_tag}:refs/tags/${setup_tag}" 2>/dev/null; then
  at=$(git rev-parse "${setup_tag}^{commit}")
  if [ "$at" != "$commit" ]; then
    refused=1
    echo "::error::${setup_tag} already exists at ${at}, not at ${commit} — a wizard release is never re-cut under a number that already shipped; bump the version and release again"
    exit 1
  fi
  echo "${setup_tag} already exists at ${commit} — reusing it"
else
  git tag "${setup_tag}" "${commit}"
  git push origin "refs/tags/${setup_tag}"
  echo "pushed ${setup_tag} at ${commit} (a GITHUB_TOKEN tag push triggers no workflow — dispatching explicitly)"
fi

gh workflow run release-setup.yml --ref "${setup_tag}" \
  -f version="${VERSION}" -f publish_release=true
echo "dispatched release-setup.yml on ${setup_tag}: it builds all three platforms, publishes the release on the tag (which pins ${commit}), refreshes the meshharbor.itachi.fans cache, and opens an issue if it fails"
echo "verify: git ls-remote origin 'refs/tags/${setup_tag}^{}' (must be ${commit}) ; gh release view ${setup_tag} --json assets ; curl -sI https://meshharbor.itachi.fans/api/setup/windows | grep -i content-disposition"
```


## release-setup

Original path: `.github/workflows/release-setup.yml`; SHA-256: `d10d225048471d676f93efeda82d1cd18e976da66a9f9e240d180e240902b26a`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve version + tag (original line 115)

```text
set -euo pipefail
if [[ "$GITHUB_EVENT_NAME" == "push" ]]; then
  tag="${GITHUB_REF_NAME}"
  version="${tag#setup-v}"
  is_release=true
else
  version="${INPUT_VERSION:-}"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "::error::Invalid version input: '${version}' (expected N.N.N or N.N.N-rc.N)"
    exit 1
  fi
  tag="setup-v${version}"
  if [[ "${INPUT_PUBLISH_RELEASE:-}" == "true" ]]; then
    is_release=true
  else
    is_release=false
  fi
  # FR-84 S1: a dispatch ON A TAG (the lockstep job's shape) must
  # name the version that tag carries — `--ref setup-v0.4.101
  # -f version=0.4.102` would build 0.4.101's tree and call it
  # 0.4.102. The Cargo.toml check below would trip on most of
  # that too; this one names the actual mistake.
  if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME}" != "${tag}" ]]; then
    echo "::error::dispatched on tag '${GITHUB_REF_NAME}' with version '${version}' (= ${tag}) — dispatch on the tag that carries the version"
    exit 1
  fi
fi
echo "Resolved: version=${version} tag=${tag} is_release=${is_release}"
# The commit this run builds — the release's target_commitish.
# Read from the checkout rather than GITHUB_SHA: on an ANNOTATED
# tag GITHUB_SHA is the tag object, which is not a commitish.
commit=$(git rev-parse 'HEAD^{commit}')
echo "commit=${commit}" >> "$GITHUB_OUTPUT"
# #2013 — GitHub refuses a release, create OR update, whose
# target_commitish adds or changes anything under .github/workflows
# relative to the default branch: the call then needs the `workflows`
# permission, which GITHUB_TOKEN can never have. It answers "Resource
# not accessible by integration" although the job holds contents:
# write. setup-v0.4.128 hit it: master changed one line of ci.yml 13
# minutes after the tagged commit. Once the tag exists it pins the
# commit, and target_commitish is only metadata — so send it ONLY when
# this release must CREATE the tag (a branch dispatch with
# publish_release=true).
if git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
  target_commitish=""
  echo "${tag} exists: the release attaches to it, without a target_commitish (#2013)"
else
  target_commitish="${commit}"
  echo "${tag} does not exist yet: the release creates it at ${commit}"
fi
echo "target_commitish=${target_commitish}" >> "$GITHUB_OUTPUT"
cargo_version=$(awk '
  /^\[workspace\.package\]/ {in_section=1; next}
  /^\[/ {in_section=0}
  in_section && /^version[[:space:]]*=/ {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)
echo "Cargo.toml workspace version: ${cargo_version}"
if [[ "${cargo_version}" != "${version}" ]]; then
  echo "::error::Version mismatch: requested ${version} but Cargo.toml has ${cargo_version}"
  exit 1
fi
echo "version=${version}" >> "$GITHUB_OUTPUT"
echo "tag=${tag}"         >> "$GITHUB_OUTPUT"
echo "is_release=${is_release}" >> "$GITHUB_OUTPUT"
```


### Archived step: Install Tauri Linux system deps (original line 212)

```text
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  libwebkit2gtk-4.1-dev \
  libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev \
  librsvg2-dev \
  libayatana-appindicator3-dev \
  patchelf
```


### Archived step: Build wizard (release) (original line 222)

```text
cargo build -p meshharbor-setup --release
```


### Archived step: Strip binary (original line 224)

```text
strip target/release/meshharbor-setup
```


### Archived step: Pack tarball (original line 228)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-setup-${version}-x86_64-unknown-linux-gnu"
mkdir -p "/tmp/${name}"
cp target/release/meshharbor-setup "/tmp/${name}/"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
(cd /tmp && tar czf "${name}.tar.gz" "${name}")
sha256sum "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Install Tauri Linux system deps (original line 275)

```text
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  libwebkit2gtk-4.1-dev \
  libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev \
  librsvg2-dev \
  libayatana-appindicator3-dev \
  patchelf
```


### Archived step: Build wizard (release) (original line 285)

```text
cargo build -p meshharbor-setup --release
```


### Archived step: Strip binary (original line 287)

```text
strip target/release/meshharbor-setup
```


### Archived step: Smoke — the binary is aarch64 and links against this base (original line 293)

```text
set -euo pipefail
readelf -h target/release/meshharbor-setup | grep -q 'Machine:.*AArch64'
if ldd target/release/meshharbor-setup | grep 'not found'; then exit 1; fi
```


### Archived step: Pack tarball (original line 300)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-setup-${version}-aarch64-unknown-linux-gnu"
mkdir -p "/tmp/${name}"
cp target/release/meshharbor-setup "/tmp/${name}/"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
(cd /tmp && tar czf "${name}.tar.gz" "${name}")
sha256sum "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Build wizard x86_64 (original line 345)

```text
cargo build -p meshharbor-setup --release --target x86_64-apple-darwin
```


### Archived step: Build wizard aarch64 (original line 347)

```text
cargo build -p meshharbor-setup --release --target aarch64-apple-darwin
```


### Archived step: Lipo into universal (original line 349)

```text
mkdir -p target/release-universal
lipo -create -output target/release-universal/meshharbor-setup \
  target/x86_64-apple-darwin/release/meshharbor-setup \
  target/aarch64-apple-darwin/release/meshharbor-setup
strip target/release-universal/meshharbor-setup
file target/release-universal/meshharbor-setup
```


### Archived step: Stage .app bundle (original line 370)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
APP="/tmp/stage/MeshHarbor Setup.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release-universal/meshharbor-setup "$APP/Contents/MacOS/meshharbor-setup"
chmod 755 "$APP/Contents/MacOS/meshharbor-setup"
# FR-84 S2: the bundle's icon (Finder, Dock, the Gatekeeper dialog),
# staged BEFORE signing so it is inside the sealed contents — the
# same PNG + CFBundleIconFile shape the companion .app uses in
# release-agent.yml.
cp agents/meshharbor-setup/icons/icon.png "$APP/Contents/Resources/icon.png"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>          <string>meshharbor-setup</string>
    <key>CFBundleIdentifier</key>          <string>fans.itachi.meshharbor.setup</string>
    <key>CFBundleName</key>                <string>MeshHarbor Setup</string>
    <key>CFBundleShortVersionString</key>  <string>${version}</string>
    <key>CFBundleVersion</key>             <string>${version}</string>
    <key>CFBundlePackageType</key>         <string>APPL</string>
    <key>CFBundleIconFile</key>            <string>icon.png</string>
    <key>LSMinimumSystemVersion</key>      <string>12.0</string>
    <key>NSPrincipalClass</key>            <string>NSApplication</string>
</dict>
</plist>
PLIST
echo "path=$APP" >> "$GITHUB_OUTPUT"
```


### Archived step: Pack tarball (original line 416)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-setup-${version}-universal-apple-darwin"
mkdir -p "/tmp/${name}"
cp -R "/tmp/stage/MeshHarbor Setup.app" "/tmp/${name}/"
# Keep `./meshharbor-setup` working (docs + muscle memory) while the
# real, stapled code lives in the bundle.
ln -s "MeshHarbor Setup.app/Contents/MacOS/meshharbor-setup" "/tmp/${name}/meshharbor-setup"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
# `tar` preserves the symlink and the stapled ticket; COPYFILE_DISABLE
# stops bsdtar emitting ._ AppleDouble files alongside every entry.
(cd /tmp && COPYFILE_DISABLE=1 tar czf "${name}.tar.gz" "${name}")
shasum -a 256 "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Verify the stapled ticket survives a tar round-trip (original line 438)

```text
set -euo pipefail
rm -rf /tmp/roundtrip && mkdir -p /tmp/roundtrip
tar xzf "${{ steps.tar.outputs.artifact }}" -C /tmp/roundtrip
app="$(find /tmp/roundtrip -maxdepth 3 -name '*.app' -type d | head -n1)"
[ -n "$app" ] || { echo "::error::no .app found in the packed tarball"; exit 1; }
bash "$GITHUB_WORKSPACE/scripts/signing/stapler-retry.sh" validate "$app"
spctl -a -vvv "$app" 2>&1 | tee /tmp/spctl.txt
grep -q 'source=Notarized Developer ID' /tmp/spctl.txt \
  || { echo "::error::extracted wizard is not Gatekeeper-clean"; exit 1; }
```


### Archived step: Build wizard (release) (original line 495)

```text
cargo build -p meshharbor-setup --release
```


### Archived step: Pack zip (original line 522)

```text
$version = "${{ needs.validate-version.outputs.version }}"
# Stable name (no -unsigned suffix): pick_setup_asset matches on
# `contains(x86_64-pc-windows-msvc) && endsWith(.zip)`, and the
# health endpoint returns whatever filename exists — a stable
# name keeps the operator-facing URI deterministic. Signed-ness
# is a property of the EXE inside, surfaced in the release notes.
$name = "meshharbor-setup-$version-x86_64-pc-windows-msvc"
New-Item -ItemType Directory -Path "$env:RUNNER_TEMP\$name" -Force | Out-Null
Copy-Item target\release\meshharbor-setup.exe "$env:RUNNER_TEMP\$name\"
if (Test-Path LICENSE) { Copy-Item LICENSE "$env:RUNNER_TEMP\$name\" }
if (Test-Path README.md) { Copy-Item README.md "$env:RUNNER_TEMP\$name\" }
Compress-Archive -Path "$env:RUNNER_TEMP\$name\*" -DestinationPath "$name.zip"
$hash = (Get-FileHash "$name.zip" -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Out-File "$name.zip.sha256" -Encoding ascii
"artifact=$name.zip" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Flatten + list (original line 569)

```text
set -euo pipefail
mkdir -p release
find artifacts -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.sha256' \) -exec cp {} release/ \;
ls -la release/
```


### Archived step: GPG-sign release artifacts (original line 580)

```text
set -euo pipefail
if [ -z "${GPG_PRIVATE_KEY:-}" ]; then
  echo "::notice::GPG_PRIVATE_KEY not configured -- publishing without .asc signatures."
  exit 0
fi
echo "$GPG_PRIVATE_KEY" | gpg --batch --import
for f in release/*; do
  case "$f" in *.asc|*.sha256) continue ;; esac
  gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" \
      --armor --detach-sign "$f"
done
gpg --batch --armor --export > release/meshharbor-release-pubkey.asc
```


### Archived step: POST /api/releases/refresh (original line 663)

```text
set -uo pipefail
if [ -z "${TOKEN}" ]; then
  echo "::notice::MESHHARBOR_RELEASE_REFRESH_TOKEN unset (fork?); skipping cache refresh"
  exit 0
fi
for attempt in 1 2 3; do
  body=$(curl -sS -m 90 -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://meshharbor.itachi.fans/api/releases/refresh?expect_tag=${TAG}")
  if [ "$(jq -r '.all_ok' <<<"$body" 2>/dev/null)" = "true" ]; then
    jq . <<<"$body"
    echo "Release cache refreshed on every live pod for ${TAG}"
    exit 0
  fi
  echo "attempt ${attempt}: ${body:-<no response>}"
  sleep 10
done
echo "::warning::release cache refresh did not confirm on every pod for ${TAG}; the cache TTL will heal it within 15 min"
```


### Archived step: File or update the alert issue (original line 729)

```text
set -euo pipefail
run_url="${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
if [ "$REF_TYPE" = "tag" ]; then
  tag="$REF_NAME"
else
  tag="setup-v${INPUT_VERSION:-?}"
fi
version="${tag#setup-v}"
existing=$(gh issue list --repo "${{ github.repository }}" --state open \
  --search 'in:title "meshharbor-setup release failed"' --limit 1 --json number --jq '.[0].number // empty')

if [ -n "$existing" ]; then
  echo "reusing open alert #$existing"
  gh issue comment "$existing" --repo "${{ github.repository }}" \
    --body "$(printf 'Failed again on %s (%s): %s\n\nStill unresolved — /api/setup still serves the previous wizard. This issue closes automatically when a wizard release succeeds.\n' "$(date -u +%F)" "$tag" "$run_url")"
else
  gh issue create --repo "${{ github.repository }}" \
    --title "meshharbor-setup release failed — /api/setup serves a stale wizard ($(date -u +%F))" \
    --body "$(printf 'The meshharbor-setup wizard release for `%s` (ref `%s`) failed: %s\n\n`/api/setup/{windows,linux,macos}` keep serving the PREVIOUS `setup-v*` release until one exists for this version — the landing page download and the admin UI both go through it, so every new install gets a wizard older than the daemon it installs (FR-84 S1 is what makes this lane run in lockstep with the agent).\n\nRe-run once fixed (the tag already exists at the agent commit; the run is idempotent):\n\n    gh workflow run release-setup.yml --ref %s -f version=%s -f publish_release=true\n\nNever re-cut a wizard under a number that already shipped — bump the version and release again.\n\nThis issue is reused by later failures and CLOSED automatically by the next successful wizard release, so an open one always means "currently broken".\n' "$tag" "$REF_NAME" "$run_url" "$tag" "$version")"
fi
```


### Archived step: Close any open wizard-release alert (original line 768)

```text
set -euo pipefail
run_url="${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
nums=$(gh issue list --repo "${{ github.repository }}" --state open \
  --search 'in:title "meshharbor-setup release failed"' --limit 50 --json number --jq '.[].number')
if [ -z "$nums" ]; then
  echo "no open wizard-release alert — nothing to close"
  exit 0
fi
for n in $nums; do
  echo "closing #$n"
  gh issue close "$n" --repo "${{ github.repository }}" --reason completed \
    --comment "$(printf '%s published on %s: %s\n\n/api/setup serves the current wizard again, so the condition this issue reports no longer holds. Closed automatically; a later failure opens a new issue.\n' "$TAG" "$(date -u +%F)" "$run_url")"
done
```


## release-tunnel

Original path: `.github/workflows/release-tunnel.yml`; SHA-256: `61adf6d7f65694c5423aa18f2193696d9a561de1513ac3ea10a7df6571dd9c0c`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve version + tag (original line 89)

```text
set -euo pipefail
if [[ "$GITHUB_EVENT_NAME" == "push" ]]; then
  tag="${GITHUB_REF_NAME}"
  version="${tag#tunnel-v}"
  is_release=true
else
  version="${INPUT_VERSION:-}"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "::error::Invalid version input: '${version}' (expected N.N.N or N.N.N-rc.N)"
    exit 1
  fi
  tag="tunnel-v${version}"
  if [[ "${INPUT_PUBLISH_RELEASE:-}" == "true" ]]; then
    is_release=true
  else
    is_release=false
  fi
fi
echo "Resolved: version=${version} tag=${tag} is_release=${is_release}"
cargo_version=$(awk '
  /^\[workspace\.package\]/ {in_section=1; next}
  /^\[/ {in_section=0}
  in_section && /^version[[:space:]]*=/ {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' Cargo.toml)
echo "Cargo.toml workspace version: ${cargo_version}"
if [[ "${cargo_version}" != "${version}" ]]; then
  echo "::error::Version mismatch: requested ${version} but Cargo.toml has ${cargo_version}"
  exit 1
fi
echo "version=${version}" >> "$GITHUB_OUTPUT"
echo "tag=${tag}"         >> "$GITHUB_OUTPUT"
echo "is_release=${is_release}" >> "$GITHUB_OUTPUT"
```


### Archived step: Install cargo-deb (original line 153)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
```


### Archived step: Build meshharbor-tunnel (release) (original line 155)

```text
cargo build -p meshharbor-cli --release
```


### Archived step: Strip binary (original line 158)

```text
strip target/release/mh
```


### Archived step: Pack tarball (original line 162)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-tunnel-${version}-x86_64-unknown-linux-gnu"
mkdir -p "/tmp/${name}"
# P3d Slice C: the legacy `meshharbor-tunnel` in-archive alias is retired —
# every live consumer (rc.194+ self-update, meshharbor-setup's
# find_tunnel_binary, install.sh) resolves the new `mh` name first.
# Archive NAME keeps the meshharbor-tunnel-… prefix (frozen contract).
cp target/release/mh "/tmp/${name}/"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
(cd /tmp && tar czf "${name}.tar.gz" "${name}")
sha256sum "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Build .deb (original line 179)

```text
cargo deb --no-build --no-strip
```


### Archived step: Rename .deb + checksum (original line 183)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
# FR-21 P2b: cargo-deb emits `<package>_…`, and the package is
# `meshharbor-cli` now. The DESTINATION asset name deliberately stays
# `meshharbor-tunnel-…` — a published, immutable surface that every prior
# release carries, and the updater matches on extension + arch, not
# the prefix.
src=$(ls target/debian/meshharbor-cli_*_amd64.deb | head -n1)
dst="meshharbor-tunnel-${version}-x86_64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Install cargo-deb (original line 236)

```text
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked
```


### Archived step: Build meshharbor-tunnel (release) (original line 238)

```text
cargo build -p meshharbor-cli --release
```


### Archived step: Strip binary (original line 240)

```text
strip target/release/mh
```


### Archived step: Pack tarball (original line 244)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-tunnel-${version}-aarch64-unknown-linux-gnu"
mkdir -p "/tmp/${name}"
cp target/release/mh "/tmp/${name}/"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
(cd /tmp && tar czf "${name}.tar.gz" "${name}")
sha256sum "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Build .deb (original line 257)

```text
cargo deb --no-build --no-strip
```


### Archived step: Rename .deb + checksum (original line 261)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
src=$(ls target/debian/meshharbor-cli_*_arm64.deb | head -n1)
dst="meshharbor-tunnel-${version}-aarch64-unknown-linux-gnu.deb"
mv "$src" "$dst"
sha256sum "$dst" | awk '{print $1"  "$2}' > "${dst}.sha256"
echo "artifact=${dst}" >> "$GITHUB_OUTPUT"
```


### Archived step: Smoke — the package installs here and its binary is aarch64 and runs (original line 273)

```text
set -euo pipefail
dpkg-deb --field "${{ steps.deb.outputs.artifact }}" Architecture | grep -qx arm64
sudo dpkg -i "${{ steps.deb.outputs.artifact }}"
readelf -h /usr/bin/mh | grep -q 'Machine:.*AArch64'
mh --version
sudo dpkg -r meshharbor-cli
```


### Archived step: Build meshharbor-tunnel x86_64 (original line 316)

```text
cargo build -p meshharbor-cli --release --target x86_64-apple-darwin
```


### Archived step: Build meshharbor-tunnel aarch64 (original line 318)

```text
cargo build -p meshharbor-cli --release --target aarch64-apple-darwin
```


### Archived step: Lipo into universal (original line 320)

```text
# P3d Slice B: per-target CLI binary is now `mh` (was
# `meshharbor-tunnel`); lipo the two arch builds into the new name.
mkdir -p target/release-universal
lipo -create -output target/release-universal/mh \
  target/x86_64-apple-darwin/release/mh \
  target/aarch64-apple-darwin/release/mh
strip target/release-universal/mh
file target/release-universal/mh
```


### Archived step: Pack tarball (original line 352)

```text
set -euo pipefail
version="${{ needs.validate-version.outputs.version }}"
name="meshharbor-tunnel-${version}-universal-apple-darwin"
mkdir -p "/tmp/${name}"
# P3d Slice C: legacy `meshharbor-tunnel` in-archive alias retired
# (see the Linux tarball step for the rationale).
cp target/release-universal/mh "/tmp/${name}/"
cp LICENSE README.md "/tmp/${name}/" 2>/dev/null || true
(cd /tmp && tar czf "${name}.tar.gz" "${name}")
shasum -a 256 "/tmp/${name}.tar.gz" | awk '{print $1"  "$2}' > "/tmp/${name}.tar.gz.sha256"
mv "/tmp/${name}.tar.gz" "/tmp/${name}.tar.gz.sha256" .
echo "artifact=${name}.tar.gz" >> "$GITHUB_OUTPUT"
```


### Archived step: Build meshharbor-tunnel (release) (original line 412)

```text
cargo build -p meshharbor-cli --release
```


### Archived step: Pack zip (original line 436)

```text
$version = "${{ needs.validate-version.outputs.version }}"
$name = "meshharbor-tunnel-$version-x86_64-pc-windows-msvc"
New-Item -ItemType Directory -Path "$env:RUNNER_TEMP\$name" -Force | Out-Null
# P3d Slice C: legacy `meshharbor-tunnel.exe` in-zip alias retired — rc.194+
# self-updaters and the setup wizard both extract `mh.exe` first.
# (A pre-rc.194 CLI waking from dormancy can still RUN; only its
# self-update would need a manual refresh — none live in the fleet,
# verified against prod tunnel_clients 2026-07-22.) Zip asset name
# keeps the `meshharbor-tunnel-…zip` prefix (updater/proxy prefix-agnostic).
Copy-Item target\release\mh.exe "$env:RUNNER_TEMP\$name\"
if (Test-Path LICENSE) { Copy-Item LICENSE "$env:RUNNER_TEMP\$name\" }
if (Test-Path README.md) { Copy-Item README.md "$env:RUNNER_TEMP\$name\" }
Compress-Archive -Path "$env:RUNNER_TEMP\$name\*" -DestinationPath "$name.zip"
$hash = (Get-FileHash "$name.zip" -Algorithm SHA256).Hash.ToLower()
"$hash  $name.zip" | Out-File "$name.zip.sha256" -Encoding ascii
"artifact=$name.zip" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Flatten + list (original line 481)

```text
set -euo pipefail
mkdir -p release
find artifacts -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.deb' -o -name '*.sha256' \) -exec cp {} release/ \;
ls -la release/
```


### Archived step: GPG-sign release artifacts (original line 492)

```text
set -euo pipefail
if [ -z "${GPG_PRIVATE_KEY:-}" ]; then
  echo "::notice::GPG_PRIVATE_KEY not configured -- publishing without .asc signatures."
  exit 0
fi
echo "$GPG_PRIVATE_KEY" | gpg --batch --import
for f in release/*; do
  case "$f" in *.asc|*.sha256) continue ;; esac
  gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" \
      --armor --detach-sign "$f"
done
gpg --batch --armor --export > release/meshharbor-release-pubkey.asc
```


### Archived step: POST /api/releases/refresh (original line 552)

```text
set -uo pipefail
if [ -z "${TOKEN}" ]; then
  echo "::notice::MESHHARBOR_RELEASE_REFRESH_TOKEN unset (fork?); skipping cache refresh"
  exit 0
fi
for attempt in 1 2 3; do
  body=$(curl -sS -m 90 -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://meshharbor.itachi.fans/api/releases/refresh?expect_tag=${TAG}")
  if [ "$(jq -r '.all_ok' <<<"$body" 2>/dev/null)" = "true" ]; then
    jq . <<<"$body"
    echo "Release cache refreshed on every live pod for ${TAG}"
    exit 0
  fi
  echo "attempt ${attempt}: ${body:-<no response>}"
  sleep 10
done
echo "::warning::release cache refresh did not confirm on every pod for ${TAG}; the cache TTL will heal it within 15 min"
```


## vendor-ffmpeg-windows

Original path: `.github/workflows/vendor-ffmpeg-windows.yml`; SHA-256: `636f0af0da5b9a1239cd2a8df0c34055c366d55302770b45ba0cae4a2c098917`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Build minimal FFmpeg via vcpkg overlay port (x64-windows-static-md, LGPL) (original line 50)

```text
$ErrorActionPreference = 'Stop'
$baseline = '2e6b92385d891ae14291b7b926863f74ed59a7ad'
# Same manifest/baseline lineage as the retired full build; the
# component trim happens in the overlay portfile, not here.
$manifest = @"
{
  "name": "meshharbor-ffmpeg-pin",
  "version": "0.0.1",
  "dependencies": [
    {"name": "ffmpeg", "default-features": false, "features": ["avcodec", "avformat", "swresample", "nvcodec", "qsv", "amf", "vulkan"]}
  ],
  "builtin-baseline": "$baseline"
}
"@
cd C:\vcpkg
git fetch origin
git reset --hard $baseline
# ALWAYS re-bootstrap after the reset: the runner's preinstalled
# vcpkg.exe tracks the CURRENT registry and refuses the year-old
# baseline tree ("document schema version 1 is not supported" +
# baseline.json resolution failures — hit 2026-08-15 when the
# runner image's tool moved past what the old keep-if-present
# check tolerated). bootstrap-vcpkg.bat fetches the tool version
# this tree's scripts/vcpkg-tools.json pins, so tool and tree
# always agree.
Remove-Item .\vcpkg.exe -Force -ErrorAction SilentlyContinue
.\bootstrap-vcpkg.bat -disableMetrics
.\vcpkg.exe version

# ── Overlay port: baseline ffmpeg + our configure-option injection ──
$overlayPorts = 'C:\ffmpeg-pin\overlay-ports'
New-Item -ItemType Directory -Path "$overlayPorts" -Force | Out-Null
Copy-Item -Recurse C:\vcpkg\ports\ffmpeg "$overlayPorts\ffmpeg"
$pf = "$overlayPorts\ffmpeg\portfile.cmake"
$anchor = 'set(CONFIGURE_OPTIONS "${OPTIONS} ${OPTIONS_RELEASE}")'
$content = Get-Content -Raw $pf
if (-not $content.Contains($anchor)) {
  Write-Host "::error::injection anchor not found in the baseline portfile — the baseline moved; re-derive the anchor before building"
  exit 1
}
# Order matters: FFmpeg's configure is last-wins per component
# class, so `--disable-everything` first WIPES the component
# enables the port's feature blocks appended earlier (e.g. qsv's
# own `--enable-encoder=h264_qsv --enable-decoder=h264_qsv`), and
# our explicit re-enables then turn back exactly what we ship.
# `--disable-everything` does NOT touch library selection — the
# avcodec/avformat/swresample libs stay per the manifest features.
# nvenc/amf/libvpl and d3d11va are component-class flags wiped by
# the reset, so they are re-enabled here; d3d11va is kept for the
# qsv/amf device plumbing (hwcontext) even though no decode
# hwaccels exist in this build.
# FR-78 P0: the vendor-neutral rungs. d3d12va is what the baseline
# port already passes on Windows (re-stated after the reset) and
# `vulkan` is the port's own feature (manifest above: it brings
# vcpkg's vulkan-headers, 1.4.357 >= the 1.4.317 `av1_vulkan`
# needs). Both are HEADER-only at build time and dlopen'd by
# FFmpeg at runtime (d3d12.dll / vulkan-1.dll), so the static tree
# grows no import and the agent no load-time need. av1_d3d12va
# additionally needs the SDK's AV1 encode structs
# (`d3d12va_av1_headers`, SDK 10.0.26100 — the runner's).
# FR-85 P4: `--enable-decoder=h264 --enable-encoder=aac` — the
# recorder's editor decodes a hardware encoder's H.264 in software,
# and its sound is AAC. No hevc decoder: nothing records HEVC, and
# a software HEVC implementation is what THIRD-PARTY-NOTICES says we
# do not ship. Fed whole access units, so no parser is needed.
$inject ='string(APPEND OPTIONS " --disable-everything --disable-network --disable-protocols --disable-devices --disable-filters --disable-bsfs --disable-parsers --disable-demuxers --disable-muxers --disable-decoders --disable-encoders --disable-hwaccels --enable-encoder=h264_nvenc --enable-encoder=hevc_nvenc --enable-encoder=av1_nvenc --enable-encoder=h264_qsv --enable-encoder=hevc_qsv --enable-encoder=av1_qsv --enable-encoder=vp9_qsv --enable-encoder=h264_amf --enable-encoder=hevc_amf --enable-encoder=av1_amf --enable-encoder=h264_d3d12va --enable-encoder=hevc_d3d12va --enable-encoder=av1_d3d12va --enable-encoder=h264_vulkan --enable-encoder=hevc_vulkan --enable-encoder=av1_vulkan --enable-nvenc --enable-amf --enable-libvpl --enable-d3d11va --enable-d3d12va --enable-vulkan --enable-decoder=h264 --enable-encoder=aac")' + "`n" + $anchor
$content = $content.Replace($anchor, $inject)

# ── FR-62 A2: apply the meshharbor FFmpeg source patches via the port's
#    own PATCHES list (vcpkg applies them with -p1 after extract, the
#    level the diffs were cut at). Copy each patch into the overlay
#    port dir and inject its filename after the portfile's `PATCHES`
#    keyword. Fail loudly if the anchor moved — never ship unpatched.
$patchDir = "$env:GITHUB_WORKSPACE\.github\ffmpeg-patches"
$patchFiles = Get-ChildItem "$patchDir\*.patch" -ErrorAction SilentlyContinue
if ($patchFiles) {
  if ($content -notmatch '(?m)^(\s*)PATCHES\s*\r?$') {
    Write-Host "::error::baseline ffmpeg portfile has no standalone PATCHES anchor — re-derive the injection before building"
    exit 1
  }
  foreach ($pf2 in $patchFiles) {
    Copy-Item $pf2.FullName "$overlayPorts\ffmpeg\$($pf2.Name)" -Force
  }
  $names = ($patchFiles | ForEach-Object { $_.Name } | Sort-Object)
  $inject2 = ($names | ForEach-Object { "        $_" }) -join "`n"
  $content = [regex]::Replace($content, '(?m)^(\s*)PATCHES\s*\r?$', "`${1}PATCHES`n$inject2")
  Write-Host "ffmpeg patches injected into the port PATCHES list: $($names -join ', ')"
  # Manifest (sha256 per patch) carried into the zip below.
  $manifestLines = $patchFiles | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower())  $($_.Name)"
  }
  $manifestLines -join "`n" | Set-Content -Path "$env:RUNNER_TEMP\MESHHARBOR-PATCHES.txt" -Encoding ascii -NoNewline
  Write-Host "meshharbor patch manifest:"; Get-Content "$env:RUNNER_TEMP\MESHHARBOR-PATCHES.txt"
}

Set-Content -Path $pf -Value $content -Encoding utf8
Write-Host "portfile injection applied"

# ── Overlay triplet: release-only static-md (skips the debug
#    build entirely — the shipped zip never carried debug/). ──
$overlayTriplets = 'C:\ffmpeg-pin\overlay-triplets'
New-Item -ItemType Directory -Path "$overlayTriplets" -Force | Out-Null
Copy-Item C:\vcpkg\triplets\x64-windows-static-md.cmake "$overlayTriplets\x64-windows-static-md.cmake"
Add-Content "$overlayTriplets\x64-windows-static-md.cmake" "set(VCPKG_BUILD_TYPE release)"

New-Item -ItemType Directory -Path C:\ffmpeg-pin -Force | Out-Null
$manifest | Out-File -Encoding utf8 C:\ffmpeg-pin\vcpkg.json
Push-Location C:\ffmpeg-pin
C:\vcpkg\vcpkg.exe install --triplet=x64-windows-static-md `
  --x-install-root=C:\ffmpeg-pin\installed `
  --overlay-ports=$overlayPorts --overlay-triplets=$overlayTriplets
if ($LASTEXITCODE -ne 0) { Write-Host "::error::vcpkg install ffmpeg (minimal overlay) failed"; exit 1 }
Pop-Location
$pc = 'C:\ffmpeg-pin\installed\x64-windows-static-md\lib\pkgconfig\libavcodec.pc'
if (-not (Test-Path $pc)) { Write-Host "::error::libavcodec.pc missing after install"; exit 1 }
Write-Host "=== libavcodec.pc ==="
Get-Content $pc | Select-String -Pattern '^(prefix|libdir|includedir|Version)='
```


### Archived step: Verify the trim actually happened (encoders in, registry out) (original line 171)

```text
$ErrorActionPreference = 'Stop'
$lib = 'C:\ffmpeg-pin\installed\x64-windows-static-md\lib'
# LGPL-clean, unchanged from the full build.
$gpl = Get-ChildItem $lib -Filter '*.lib' | Where-Object { $_.Name -match 'x264|x265' }
if ($gpl) { Write-Host "::error::GPL codec lib present: $($gpl.Name)"; exit 1 }
# The sixteen hardware encoders must exist, and (FR-85 P4) the
# software h264 decoder and the aac encoder the recorder's editor
# and sound need. Everything else the registry would bring must NOT.
$vsroot = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$dumpbin = Get-ChildItem "$vsroot\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" | Select-Object -Last 1
$syms = & $dumpbin.FullName /LINKERMEMBER:1 "$lib\avcodec.lib" | Out-String
foreach ($enc in @('ff_h264_nvenc_encoder','ff_hevc_nvenc_encoder','ff_av1_nvenc_encoder',
                   'ff_h264_qsv_encoder','ff_hevc_qsv_encoder','ff_av1_qsv_encoder','ff_vp9_qsv_encoder',
                   'ff_h264_amf_encoder','ff_hevc_amf_encoder','ff_av1_amf_encoder',
                   'ff_h264_d3d12va_encoder','ff_hevc_d3d12va_encoder','ff_av1_d3d12va_encoder',
                   'ff_h264_vulkan_encoder','ff_hevc_vulkan_encoder','ff_av1_vulkan_encoder',
                   'ff_h264_decoder','ff_aac_encoder')) {
  if ($syms -notmatch [regex]::Escape($enc)) { Write-Host "::error::expected component symbol missing: $enc"; exit 1 }
}
# FR-78 P0 — both new backends are dlopen'd by FFmpeg: the static
# tree must carry NO import of d3d12.dll / vulkan-1.dll, or the
# agent would fail to load on a box without them.
$imports = & $dumpbin.FullName /DIRECTIVES "$lib\avutil.lib" | Out-String
foreach ($dll in @('vulkan-1.lib','d3d12.lib')) {
  if ($imports -match [regex]::Escape($dll)) { Write-Host "::error::avutil.lib carries a link directive for $dll — the backend must stay dlopen'd"; exit 1 }
}
# FR-85 P4 — the h264 decoder is IN now; the hevc one stays out on
# purpose (nothing writes an HEVC recording, and a software HEVC
# implementation is what THIRD-PARTY-NOTICES says we do not ship).
foreach ($dead in @('ff_prores_decoder','ff_hevc_decoder')) {
  if ($syms -match [regex]::Escape($dead)) { Write-Host "::error::component that should be trimmed is present: $dead"; exit 1 }
}
# The muxers live in avformat, not avcodec: scanned there, or the
# assertion could never fire. `avformat_alloc_context` is the
# positive control that proves the scan reads the right library.
$fsyms = & $dumpbin.FullName /LINKERMEMBER:1 "$lib\avformat.lib" | Out-String
if ($fsyms -notmatch 'avformat_alloc_context') { Write-Host "::error::avformat.lib scan found no avformat_alloc_context — the muxer check below would be vacuous"; exit 1 }
if ($fsyms -match [regex]::Escape('ff_mov_muxer')) { Write-Host "::error::component that should be trimmed is present: ff_mov_muxer"; exit 1 }
$mb = [math]::Round((Get-Item "$lib\avcodec.lib").Length / 1MB, 1)
Write-Host "avcodec.lib = $mb MB (full build was 139.3; FR-85 P0 measured 38.0 with h264+hevc decoders and aac)"
if ($mb -gt 60) { Write-Host "::error::avcodec.lib is $mb MB — the trim did not take"; exit 1 }
Write-Host "trim verified: 16 encoders + the h264 decoder + the aac encoder present, registry payload gone"
```


### Archived step: Package + upload the minimal static-md tree (original line 219)

```text
$ErrorActionPreference = 'Stop'
$root = 'C:\ffmpeg-pin\installed\x64-windows-static-md'
# Ship release lib/ (static .lib + pkgconfig) + include/ only.
# NEW NAME next to the old full asset: release-agent.yml picks by
# filename, so rollback = flip the pattern back to the non-minimal
# zip (kept on the release untouched). FR-78 P0 added the
# `-d3d12-vulkan` suffix (six more encoders, no new import):
# rollback = drop that suffix. FR-85 P4 added `-h264dec-aac` (the
# software h264 decoder and the aac encoder): rollback = drop it.
$zip = "$env:RUNNER_TEMP\ffmpeg-9.0.1-win64-msvc-static-md-lgpl-minimal-d3d12-vulkan-h264dec-aac.zip"
# FR-62 A2 — carry the patch manifest inside the asset so
# release-agent can prove the vendored libs match the committed
# patches (see the build step). Present iff the build applied patches.
$paths = @("$root\lib", "$root\include")
$manifest = "$env:RUNNER_TEMP\MESHHARBOR-PATCHES.txt"
if (Test-Path $manifest) {
  Copy-Item $manifest "$root\MESHHARBOR-PATCHES.txt" -Force
  $paths += "$root\MESHHARBOR-PATCHES.txt"
}
Compress-Archive -Path $paths -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
"$hash  $(Split-Path $zip -Leaf)" | Out-File -Encoding ascii "$zip.sha256"
Write-Host "zip: $([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB  sha256=$hash"
gh release upload vendored-ffmpeg-9.0.1 $zip "$zip.sha256" --repo "${{ github.repository }}" --clobber
Write-Host "uploaded $(Split-Path $zip -Leaf) to vendored-ffmpeg-9.0.1"
```


### Archived step: Build minimal FFmpeg (shared, encoders-only) (original line 266)

```text
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y nasm pkg-config cmake ninja-build python3-pip
# meson from pip, SYSTEM-wide: libdrm/libva want a newer floor than
# 22.04's apt, and `sudo ninja install` re-runs meson as root — a
# `--user` install is invisible there (measured: the first run died
# in `meson install` with "No module named 'mesonbuild'").
sudo python3 -m pip install -q meson
# nvenc: header-only SDK, versioned; 12.1 supports Blackwell-era
# drivers while keeping the driver floor reasonable.
git clone --depth 1 --branch n13.1.15.0 https://github.com/FFmpeg/nv-codec-headers.git /tmp/nvh
sudo make -C /tmp/nvh install PREFIX=/usr/local
# qsv: Intel oneVPL dispatcher (thin; the runtime comes from the
# host's intel-media stack). ffmpeg wants libvpl >= 2.6.
git clone --depth 1 --branch v2.10.2 https://github.com/intel/libvpl.git /tmp/vpl
cmake -S /tmp/vpl -B /tmp/vpl/build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF
cmake --build /tmp/vpl/build -j"$(nproc)"
sudo cmake --install /tmp/vpl/build --prefix /usr/local
# amf: header-only.
git clone --depth 1 --branch v1.5.2 https://github.com/GPUOpen-LibrariesAndSDKs/AMF.git /tmp/amf
sudo mkdir -p /usr/local/include/AMF
sudo cp -r /tmp/amf/amf/public/include/* /usr/local/include/AMF/
sudo ldconfig
# FR-77 P4 — libdrm + libva are BUNDLED (both MIT), built into the
# same prefix as the FFmpeg libs so release-agent's ldd-fixpoint
# bundler carries them like any other vendored lib. Deliberately
# NOT the system's: `--enable-vaapi` makes libva.so.2 a DT_NEEDED
# of libavutil, i.e. a LOAD-time requirement of the daemon
# binary. A hard `Depends: libva2` satisfies that only where apt
# can reach a mirror — the updater's offline fallback is
# `dpkg --install`, which REPLACES the binary before the
# dependency failure and leaves a host whose daemon cannot start
# on its next restart: a fleet freeze, not an error. The VA
# DRIVER (iHD / radeonsi / nouveau) stays the host's — libva is
# only the dispatcher that dlopens it, and its one coupling to a
# driver is the `__vaDriverInit_1_<minor>` lookup, which walks
# DOWN from the loader's own minor: the NEWEST libva loads every
# driver built against an older one, and a driver built against
# a newer libva than ours fails to load (no VAAPI cells, not a
# crash) until the next re-vendor. `driverdir` names the distros'
# driver dirs (Debian multiarch, Fedora, Arch; the loader splits
# on ':') because the default would point INTO this prefix, where
# no driver ever lives; LIBVA_DRIVERS_PATH still overrides.
curl -sL -o /tmp/libdrm.tar.xz https://dri.freedesktop.org/libdrm/libdrm-2.4.134.tar.xz
mkdir -p /tmp/libdrm && tar xf /tmp/libdrm.tar.xz -C /tmp/libdrm --strip-components=1
meson setup /tmp/libdrm/build /tmp/libdrm --prefix=/opt/ffout --libdir=lib --buildtype=release \
  -Dtests=false -Dman-pages=disabled -Dvalgrind=disabled -Dcairo-tests=disabled
ninja -C /tmp/libdrm/build
sudo ninja -C /tmp/libdrm/build install
curl -sL -o /tmp/libva.tar.gz https://github.com/intel/libva/archive/refs/tags/2.24.1.tar.gz
mkdir -p /tmp/libva && tar xf /tmp/libva.tar.gz -C /tmp/libva --strip-components=1
PKG_CONFIG_PATH=/opt/ffout/lib/pkgconfig meson setup /tmp/libva/build /tmp/libva \
  --prefix=/opt/ffout --libdir=lib --buildtype=release \
  -Dwith_x11=no -Dwith_glx=no -Dwith_wayland=no -Denable_docs=false \
  -Ddriverdir=/usr/lib/x86_64-linux-gnu/dri:/usr/lib64/dri:/usr/lib/dri
ninja -C /tmp/libva/build
sudo ninja -C /tmp/libva/build install
test -f /opt/ffout/lib/libva-drm.so.2 || { echo "::error::libva-drm did not build — libdrm not found by libva's meson?"; exit 1; }
# FR-78 P0 — Vulkan video encode needs only the Vulkan HEADERS at
# build time (FFmpeg dlopens libvulkan.so.1 at runtime; configure's
# check is header-only): 22.04's libvulkan-dev is 1.3.204, far below
# the 1.4.317 `av1_vulkan` wants, so the C headers come from the
# Khronos repo at a pinned tag, into the prefix (staged with the
# tree like va/, so a bindgen of hwcontext_vulkan.h resolves).
git clone --depth 1 --branch v1.4.362 https://github.com/KhronosGroup/Vulkan-Headers.git /tmp/vkh
sudo mkdir -p /opt/ffout/include/vulkan /opt/ffout/include/vk_video
sudo cp /tmp/vkh/include/vulkan/*.h /opt/ffout/include/vulkan/
sudo cp /tmp/vkh/include/vk_video/*.h /opt/ffout/include/vk_video/
grep -q "VK_HEADER_VERSION 362" /opt/ffout/include/vulkan/vulkan_core.h || { echo "::error::Vulkan headers are not the pinned 1.4.362"; exit 1; }

curl -sL -o /tmp/ffmpeg.tar.gz https://github.com/FFmpeg/FFmpeg/archive/refs/tags/n9.0.1.tar.gz
mkdir -p /tmp/ffsrc && tar xf /tmp/ffmpeg.tar.gz -C /tmp/ffsrc --strip-components=1
cd /tmp/ffsrc
# FR-62 A2 — apply every meshharbor FFmpeg source patch (patch -p1 from
# the source root, the same level the diffs were cut at) BEFORE
# configure, and record a manifest (sha256 per patch) that
# release-agent asserts against the committed patches so a stale
# vendored asset can never ship. `patch --fatal-on-nonmatch` via the
# `|| exit 1` — a patch that does not apply cleanly must FAIL the
# build, never silently ship an unpatched lib.
shopt -s nullglob
for p in "$GITHUB_WORKSPACE"/.github/ffmpeg-patches/*.patch; do
  echo "ffmpeg patch: applying $(basename "$p")"
  patch -p1 --no-backup-if-mismatch < "$p" || { echo "::error::patch $(basename "$p") failed to apply to n9.0.1"; exit 1; }
done
( cd "$GITHUB_WORKSPACE" && sha256sum .github/ffmpeg-patches/*.patch 2>/dev/null | sed 's#\.github/ffmpeg-patches/##' ) > /tmp/MESHHARBOR-PATCHES.txt || true
echo "meshharbor patch manifest:"; cat /tmp/MESHHARBOR-PATCHES.txt
# /opt/ffout first: configure must find the BUNDLED libva/libdrm
# (FR-77 P4), never the runner's own copies.
export PKG_CONFIG_PATH=/opt/ffout/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:${PKG_CONFIG_PATH:-}
# Same trim as the Windows overlay port: --disable-everything wipes
# every component; the explicit enables restore exactly the seventeen
# HW encoders the agent dispatches (FR-78 P0: + the three Vulkan
# ones, header-only at build time, dlopen'd at runtime; the
# spirv-headers warning is about swscale, which is off).
# Library-level: avformat kept
# (ffmpeg-next's `format` feature probes its .pc; rc.71),
# swresample kept (avcodec requires it); avdevice/avfilter/swscale
# dropped. --disable-autodetect keeps host libs out so the result
# is reproducible and dependency-clean (nvenc/vpl/amf explicit).
./configure --prefix=/opt/ffout \
  --enable-shared --disable-static --disable-programs --disable-doc \
  --disable-autodetect \
  --disable-everything --disable-network --disable-protocols \
  --disable-devices --disable-filters --disable-bsfs --disable-parsers \
  --disable-demuxers --disable-muxers --disable-decoders \
  --disable-encoders --disable-hwaccels \
  --disable-avdevice --disable-avfilter --disable-swscale \
  --enable-encoder=h264_nvenc,hevc_nvenc,av1_nvenc,h264_qsv,hevc_qsv,av1_qsv,vp9_qsv,h264_amf,hevc_amf,av1_amf,h264_vaapi,hevc_vaapi,av1_vaapi,vp9_vaapi,h264_vulkan,hevc_vulkan,av1_vulkan \
  --enable-nvenc --enable-ffnvcodec --enable-cuda --enable-libvpl --enable-amf --enable-vaapi --enable-vulkan \
  --extra-cflags=-I/opt/ffout/include \
  --enable-parser=h264,hevc,av1 \
  --enable-decoder=h264 --enable-encoder=aac \
  || { echo "=== configure failed; last errors in config.log ==="; grep -n -B 25 "^ERROR:" ffbuild/config.log | tail -80; grep -nE "error:" ffbuild/config.log | tail -10; exit 1; }
make -j"$(nproc)"
sudo make install
echo "=== installed libs ==="
ls -la /opt/ffout/lib/ | grep -E "\.so"
```


### Archived step: Verify the trim (runtime probe — the version script hides ff_* symbols) (original line 387)

```text
set -euo pipefail
cat > /tmp/probe.c <<'EOC'
#include <libavcodec/avcodec.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  const char *want[] = {"h264_nvenc","hevc_nvenc","av1_nvenc","h264_qsv","hevc_qsv",
                        "av1_qsv","vp9_qsv","h264_amf","hevc_amf","av1_amf",
                        "h264_vaapi","hevc_vaapi","av1_vaapi","vp9_vaapi",
                        "h264_vulkan","hevc_vulkan","av1_vulkan"};
  for (unsigned i = 0; i < sizeof(want)/sizeof(*want); i++) {
    if (!avcodec_find_encoder_by_name(want[i])) { fprintf(stderr, "MISSING encoder %s\n", want[i]); return 1; }
  }
  /* FR-85 P4 — the recorder's editor decodes H.264 in software and its
     sound is AAC: both must be IN. HEVC decoding stays OUT on purpose
     (nothing records HEVC; THIRD-PARTY-NOTICES ships no software HEVC). */
  if (!avcodec_find_decoder_by_name("h264")) { fprintf(stderr, "MISSING decoder h264\n"); return 1; }
  if (!avcodec_find_encoder_by_name("aac")) { fprintf(stderr, "MISSING encoder aac\n"); return 1; }
  if (avcodec_find_decoder_by_name("hevc")) { fprintf(stderr, "hevc DECODER present — trim did not take\n"); return 1; }
  if (avcodec_find_encoder_by_name("libkvazaar")) { fprintf(stderr, "libkvazaar present — trim did not take\n"); return 1; }
  printf("probe OK: 17 encoders + the h264 decoder + the aac encoder present, registry trimmed\n");
  return 0;
}
EOC
# -rpath-link: ld resolves the avcodec/avutil DT_NEEDED chain (now
# the BUNDLED libva, FR-77 P4) from rpath-link dirs, never from -L —
# without it the probe link dies on `undefined reference to
# vaErrorStr` while the libs themselves are fine (measured).
gcc /tmp/probe.c -o /tmp/probe \
  -I/opt/ffout/include -L/opt/ffout/lib -Wl,-rpath-link,/opt/ffout/lib -lavcodec -lavutil
LD_LIBRARY_PATH=/opt/ffout/lib /tmp/probe
# FR-77 P4 — every VAAPI call must go through the BUNDLED libva
# (the runner has a system copy too, from its preinstalled ffmpeg),
# and that libva must look for drivers where the distros put them.
LD_LIBRARY_PATH=/opt/ffout/lib ldd /opt/ffout/lib/libavutil.so | grep -E "libva(-drm)?\.so\.2|libdrm\.so\.2" | tee /tmp/va-ldd.txt
[ "$(grep -c "=> /opt/ffout/lib/" /tmp/va-ldd.txt)" -eq 3 ] || { echo "::error::libva / libva-drm / libdrm do not all resolve from the vendored tree"; exit 1; }
strings /opt/ffout/lib/libva.so.2 | grep -q "x86_64-linux-gnu/dri" || { echo "::error::the bundled libva does not search the distro driver dir (driverdir)"; exit 1; }
# LGPL-clean + no unexpected external deps beyond glibc/vpl.
ldd /opt/ffout/lib/libavcodec.so | grep -E "x264|x265" && { echo "::error::GPL lib linked"; exit 1; } || true
# FR-78 P0 — Vulkan is dlopen'd: libvulkan must NOT be a DT_NEEDED
# of any vendored lib (a host without a Vulkan loader would fail to
# load the daemon instead of losing three cells).
for l in /opt/ffout/lib/libavcodec.so /opt/ffout/lib/libavutil.so; do
  ldd "$l" | grep -q "libvulkan" && { echo "::error::$(basename "$l") links libvulkan — the backend must stay dlopen'd"; exit 1; } || true
done
du -sh /opt/ffout/lib | cut -f1
```


### Archived step: Package + upload the minimal shared tree (original line 438)

```text
set -euo pipefail
# Top-level dir so release-agent's `--strip-components=1` extract
# keeps working; the fetch step sed-rewrites the .pc prefixes.
staging=/tmp/stage/ffmpeg-minimal
mkdir -p "$staging"
cp -a /opt/ffout/lib /opt/ffout/include "$staging/"
# libvpl.so.2 is a DT_NEEDED of the minimal avcodec (qsv) and was
# BUILT here into /usr/local — the runtime probe above resolves it
# from the build host, but a stock target box has no libvpl at all
# (rehearsal-proven: the 24.04 load check died on exactly this).
# Staging it next to the FFmpeg libs lets release-agent's
# ldd-fixpoint bundler pick it up like any other vendored lib.
find /usr/local/lib /usr/local/lib64 -maxdepth 1 -name 'libvpl.so*' -exec cp -a {} "$staging/lib/" \; 2>/dev/null || true
ls "$staging/lib/" | grep -q "libvpl.so.2" || { echo "::error::libvpl runtime not staged — the .deb would fail to load on stock hosts"; exit 1; }
# FR-77 P4 — the bundled VA loader chain (built into /opt/ffout
# above, so `cp -a` already staged it); asserted because a tree
# without it would make libva.so.2 a SYSTEM requirement again.
for l in libva.so.2 libva-drm.so.2 libdrm.so.2; do
  ls "$staging/lib/" | grep -q "^$l" || { echo "::error::$l not staged — the daemon would need the system's libva (FR-77 P4 bundles it)"; exit 1; }
done
# Belt-and-braces: every DT_NEEDED of the staged avcodec must
# resolve from the staging dir or glibc-family alone.
LD_LIBRARY_PATH="$staging/lib" ldd "$staging"/lib/libavcodec.so | grep "not found" && { echo "::error::unresolvable DT_NEEDED in staged libavcodec"; exit 1; } || true
# FR-62 A2 — carry the patch manifest inside the asset so
# release-agent can prove the vendored libs match the committed
# patches before it ships them.
cp /tmp/MESHHARBOR-PATCHES.txt "$staging/MESHHARBOR-PATCHES.txt"
# FR-78 P0: `-vulkan` suffix (three more encoders, no new DT_NEEDED);
# rollback = drop it. FR-85 P4: `-h264dec-aac` (the software h264
# decoder and the aac encoder, inside libavcodec, no new DT_NEEDED);
# rollback = drop it.
tar cJf /tmp/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz -C /tmp/stage ffmpeg-minimal
sha256sum /tmp/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz | tee /tmp/min.sha256
ls -la /tmp/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz
gh release upload vendored-ffmpeg-9.0.1 \
  /tmp/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz \
  --repo "${{ github.repository }}" --clobber
```


## vendor-ffmpeg-macos

Original path: `.github/workflows/vendor-ffmpeg-macos.yml`; SHA-256: `97539c71a8fbb5eeb02421372b4469e3834099e27c9d6a4d9e289561c63f0879`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Install build deps (original line 54)

```text
brew install nasm
```


### Archived step: Build LGPL FFmpeg (shared, VideoToolbox, @rpath install names) (original line 62)

```text
set -euo pipefail
REF="${INPUT_FFMPEG_REF:-}"
# A git ref, not a shell fragment: it is interpolated into a clone
# below and must not carry metacharacters.
if [[ ! "$REF" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "::error::Invalid ffmpeg_ref: '${REF}'"
  exit 1
fi
git clone --depth 1 --branch "$REF" https://github.com/FFmpeg/FFmpeg.git ffsrc
cd ffsrc
echo "FFmpeg source: $(git describe --tags --always)"
OUT="$RUNNER_TEMP/ffout"
# Same trim as the Windows overlay port and the Linux minimal build:
# --disable-everything wipes every component, then the explicit
# enables restore exactly the encoders `encode/ffmpeg/encoder.rs`
# dispatches here. avformat is kept (ffmpeg-next's `format` feature
# probes its .pc) and swresample is required by avcodec;
# avdevice/avfilter/swscale are dropped.
#
# --disable-autodetect is the load-bearing one for the rc.453 crash
# class: it stops configure picking up whatever the RUNNER happens to
# have. Homebrew X11 was baked into six dylibs exactly that way, and
# dyld then killed the agent at launch on every end-user Mac.
# --disable-xlib/--disable-libxcb stay as belt-and-braces; the
# sanity step below is what makes the prevention enforceable.
#
# --enable-videotoolbox comes AFTER --disable-autodetect so it is
# re-enabled explicitly; it is OS-SDK, so it adds no dependency.
./configure \
  --prefix="$OUT" \
  --enable-shared --disable-static \
  --disable-gpl --disable-nonfree \
  --disable-programs --disable-doc --disable-debug \
  --disable-autodetect \
  --disable-everything --disable-network --disable-protocols \
  --disable-devices --disable-filters --disable-bsfs --disable-parsers \
  --disable-demuxers --disable-muxers --disable-decoders \
  --disable-encoders --disable-hwaccels \
  --disable-avdevice --disable-avfilter --disable-swscale \
  --disable-xlib --disable-libxcb \
  --enable-videotoolbox \
  --enable-encoder=h264_videotoolbox,hevc_videotoolbox,av1_videotoolbox \
  --enable-parser=h264,hevc,av1 \
  --enable-decoder=h264 --enable-encoder=aac \
  --install-name-dir=@rpath \
  --enable-pic \
  || { echo "=== configure failed; last errors in config.log ==="; \
       grep -n -B 25 "^ERROR:" ffbuild/config.log | tail -80; \
       grep -nE "error:" ffbuild/config.log | tail -10; exit 1; }
make -j"$(sysctl -n hw.ncpu)"
make install
echo "OUT=$OUT" >> "$GITHUB_ENV"
```


### Archived step: Sanity-check the build (arm64 dylibs, @rpath install names, no GPL) (original line 117)

```text
set -euo pipefail
cd "$OUT"
echo "=== dylibs ==="; ls -1 lib/*.dylib
echo "=== libavcodec arch + install_name (want arm64 + @rpath) ==="
lipo -info lib/libavcodec.*.dylib | head -1
otool -D lib/libavcodec.*.dylib | tail -1
echo "=== libavcodec sibling deps (want @rpath/libav*) ==="
otool -L lib/libavcodec.*.dylib | grep -E '@rpath|/opt|/usr/local' || true

echo "=== no dylib may depend on Homebrew ==="
# This check used to print `/opt` hits and swallow them with `|| true`,
# and the 2026-08-22 artifact did contain them: configure autodetected
# the runner's Homebrew X11, baking /opt/homebrew/opt/libx11/... into
# six of the seven dylibs (and four libxcb* into libavdevice). Nothing
# on an end-user Mac provides those, so the agent that bundled them
# was killed by dyld at launch. `--disable-xlib --disable-libxcb`
# above prevents it; this makes the prevention enforceable.
bad=0
for so in lib/*.dylib; do
  refs="$(otool -L "$so" | tail -n +2 | awk '{print $1}' \
          | grep -E '^/(opt|usr/local)/' || true)"
  if [ -n "$refs" ]; then
    echo "::error::$so depends on a non-system path:"; echo "$refs" | sed 's/^/    /'
    bad=1
  fi
done
[ "$bad" -eq 0 ] || exit 1
echo "  clean — system frameworks and @rpath siblings only."
echo "=== confirm NO GPL encoders linked (no libx264/libx265) ==="
if otool -L lib/libavcodec.*.dylib | grep -Ei 'x264|x265'; then
  echo "::error::GPL codec linked — build is not LGPL-clean"; exit 1
fi
echo "  LGPL-clean."
```


### Archived step: Verify the trim (runtime probe — a symbol scan cannot see this) (original line 153)

```text
set -euo pipefail
# MUST be a runtime `avcodec_find_encoder_by_name`, not `nm`: the
# version script hides `ff_*` from the symbol table, so a symbol scan
# reports absent for encoders that are present. Only asking the
# registry is evidence.
cat > /tmp/probe.c <<'EOC'
#include <libavcodec/avcodec.h>
#include <stdio.h>
int main(void) {
  /* REQUIRED: the two Apple silicon actually has encode blocks for. */
  const char *want[] = {"h264_videotoolbox","hevc_videotoolbox"};
  for (unsigned i = 0; i < sizeof(want)/sizeof(*want); i++) {
    if (!avcodec_find_encoder_by_name(want[i])) {
      fprintf(stderr, "MISSING encoder %s\n", want[i]); return 1;
    }
  }
  /* OPTIONAL: av1_videotoolbox. It stays in --enable-encoder so a
     future runner/SDK builds it automatically, but it is NOT
     required — measured 2026-08-24 on macos-14, the registry does
     not hand it out even though libavcodec carries a
     "VideoToolbox AV1 Encoder" long-name string. That is precisely
     why this check is a runtime registry lookup and not a symbol
     scan: the string is present, the encoder is not. Report it so a
     future SDK flipping this is visible in the log. */
  printf("av1_videotoolbox: %s\n",
         avcodec_find_encoder_by_name("av1_videotoolbox")
           ? "PRESENT (new — the Rust dispatch rung is now live)"
           : "absent (expected on current SDKs)");
  /* And the trim must actually have taken — if a general decoder or
     an unrelated encoder survived, --disable-everything did not
     apply and this is the fat tree again. */
  /* FR-85 P4 — the recorder's editor decodes H.264 in software and its
     sound is AAC: both must be IN. HEVC decoding stays OUT on purpose
     (nothing records HEVC; THIRD-PARTY-NOTICES ships no software HEVC). */
  if (!avcodec_find_decoder_by_name("h264")) {
    fprintf(stderr, "MISSING decoder h264\n"); return 1;
  }
  if (!avcodec_find_encoder_by_name("aac")) {
    fprintf(stderr, "MISSING encoder aac\n"); return 1;
  }
  if (avcodec_find_decoder_by_name("hevc")) {
    fprintf(stderr, "hevc DECODER present — trim did not take\n"); return 1;
  }
  if (avcodec_find_encoder_by_name("mpeg4")) {
    fprintf(stderr, "mpeg4 encoder present — trim did not take\n"); return 1;
  }
  printf("probe OK: required videotoolbox encoders + the h264 decoder + the aac encoder present, registry trimmed\n");
  return 0;
}
EOC
# `@rpath` install names, so the probe binary needs its own rpath.
clang /tmp/probe.c -o /tmp/probe \
  -I"$OUT/include" -L"$OUT/lib" -lavcodec -lavutil \
  -Wl,-rpath,"$OUT/lib"
/tmp/probe
echo "=== dylib set + size (untrimmed was ~20 MB; libavcodec 12.85 MB) ==="
ls -1 "$OUT/lib"/*.dylib | sed 's|.*/|    |'
du -sh "$OUT/lib" | cut -f1
```


### Archived step: Package tarball (original line 214)

```text
set -euo pipefail
cd "$OUT"
# FR-85 P4: `-h264dec-aac` (the software h264 decoder and the aac
# encoder) is this asset's first suffix; release-agent.yml picks by
# name, so rollback = drop it (the unsuffixed tarball stays).
TAR="ffmpeg-9.0.1-macos-arm64-lgpl-shared-h264dec-aac.tar.xz"
tar cJf "$RUNNER_TEMP/$TAR" lib include
cd "$RUNNER_TEMP"
shasum -a 256 "$TAR" | tee "$TAR.sha256"
echo "TAR=$RUNNER_TEMP/$TAR" >> "$GITHUB_ENV"
echo "size: $(du -h "$TAR" | cut -f1)"
```


### Archived step: Upload to the vendored-ffmpeg-9.0.1 release (original line 230)

```text
set -euo pipefail
gh release upload vendored-ffmpeg-9.0.1 \
  "$TAR" "$TAR.sha256" \
  --repo "${{ github.repository }}" --clobber
echo "uploaded $(basename "$TAR") to vendored-ffmpeg-9.0.1"
```


## vendor-libvpx-windows

Original path: `.github/workflows/vendor-libvpx-windows.yml`; SHA-256: `12a43b926093f3e76eb9c0a5c0d0f3f2734765f78cfddfb1b4705f3f06093399`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Build libvpx 1.12.0 via vcpkg (x64-windows) (original line 29)

```text
$ErrorActionPreference = 'Stop'
# Identical manifest + baseline to the (removed) inline
# build-windows step. 1.12.0 pinned because env-libvpx-sys picks
# its pre-generated FFI file by pkg-config's reported version
# EXACTLY (1.13.0 was bumped to 1.13.1 in vcpkg, which has no
# pre-generated file).
if (-not (Test-Path 'C:\vcpkg\vcpkg.exe')) {
  git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
  C:\vcpkg\bootstrap-vcpkg.bat -disableMetrics
} else {
  Write-Host "Using pre-installed vcpkg at C:\vcpkg"
}
# Need full history to resolve the 1.12.0 baseline (the baseline
# commit must contain the version-specific git-tree entry vcpkg
# looks up). `git fetch --unshallow` errors on already-complete
# repos, so probe first.
if ((git -C C:\vcpkg rev-parse --is-shallow-repository) -eq 'true') {
  git -C C:\vcpkg fetch --unshallow
} else {
  git -C C:\vcpkg fetch --tags
}
New-Item -ItemType Directory -Path C:\vpx-pin -Force | Out-Null
@'
{
  "name": "meshharbor-vpx-pin",
  "version": "0.0.1",
  "dependencies": [{"name": "libvpx", "version>=": "1.12.0"}],
  "overrides":    [{"name": "libvpx", "version":   "1.12.0"}],
  "builtin-baseline": "4d73751b3428ef49a7ac5d5df696b92e302de993"
}
'@ | Set-Content -Encoding utf8 C:\vpx-pin\vcpkg.json
Push-Location C:\vpx-pin
C:\vcpkg\vcpkg.exe install --triplet=x64-windows --x-install-root=C:\vpx-pin\installed
if ($LASTEXITCODE -ne 0) { Write-Host "::error::vcpkg install libvpx failed"; exit 1 }
Pop-Location
```


### Archived step: Assert vpx.pc reports exactly 1.12.0 (original line 68)

```text
$ErrorActionPreference = 'Stop'
$pc = 'C:\vpx-pin\installed\x64-windows\lib\pkgconfig\vpx.pc'
if (-not (Test-Path $pc)) { Write-Host "::error::vpx.pc missing after install"; exit 1 }
$ver = ((Get-Content $pc | Select-String '^Version:').Line -replace '^Version:\s*', '').Trim()
Write-Host "vpx.pc Version: $ver"
if ($ver -ne '1.12.0') {
  Write-Host "::error::vpx.pc reports '$ver' but env-libvpx-sys's pre-generated bindings need exactly 1.12.0"
  exit 1
}
```


### Archived step: Package + upload the x64-windows tree (original line 83)

```text
$ErrorActionPreference = 'Stop'
$root = 'C:\vpx-pin\installed\x64-windows'
# lib/ (static vpx.lib + pkgconfig) + include/ — plus bin/ only if
# the port ever produces a DLL (today it's static-only, and
# Compress-Archive errors on nonexistent paths). debug/ dropped to
# keep the artifact lean.
$paths = @("$root\lib", "$root\include")
if (Test-Path "$root\bin") { $paths += "$root\bin" }
$zip = "$env:RUNNER_TEMP\libvpx-1.12.0-win64-msvc.zip"
Compress-Archive -Path $paths -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
"$hash  $(Split-Path $zip -Leaf)" | Out-File -Encoding ascii "$zip.sha256"
Write-Host "zip: $([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB  sha256=$hash"
# Create the release if absent. --latest=false is CRITICAL: fielded
# agents poll /releases/latest for self-update — a vendored-deps
# release must never shadow an agent release there.
$ErrorActionPreference = 'Continue'
gh release view vendored-libvpx-1.12.0 --repo "${{ github.repository }}" *> $null
$exists = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = 'Stop'
if (-not $exists) {
  gh release create vendored-libvpx-1.12.0 --repo "${{ github.repository }}" `
    --title "Vendored libvpx 1.12.0 (build dep)" `
    --notes "Prebuilt libvpx 1.12.0 (x64-windows, vcpkg baseline 4d73751b) consumed by release-agent.yml's build-windows job. Not an agent release." `
    --latest=false
  if ($LASTEXITCODE -ne 0) { Write-Host "::error::gh release create failed"; exit 1 }
}
gh release upload vendored-libvpx-1.12.0 $zip "$zip.sha256" --repo "${{ github.repository }}" --clobber
if ($LASTEXITCODE -ne 0) { Write-Host "::error::gh release upload failed"; exit 1 }
Write-Host "uploaded $(Split-Path $zip -Leaf) to vendored-libvpx-1.12.0"
```


## lgpl-source-offer

Original path: `.github/workflows/lgpl-source-offer.yml`; SHA-256: `2cb4faf874227fa0abbd2c2c7b6069e1a27d2c556c65bd703bd6f8e7b4d18e8b`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Fetch pristine upstream source (original line 55)

```text
set -euo pipefail
V='${{ inputs.ffmpeg_version }}'
mkdir -p bundle
curl -fsSL -o "bundle/ffmpeg-$V.tar.gz" \
  "https://github.com/FFmpeg/FFmpeg/archive/refs/tags/$V.tar.gz"
# Archive our OWN copy: an upstream tag can be moved or removed, and a
# three-year offer cannot depend on someone else's hosting.
echo "source: $(du -h "bundle/ffmpeg-$V.tar.gz" | cut -f1)"
```


### Archived step: Archive every change the builds make to that source (original line 68)

```text
set -euo pipefail
V='${{ inputs.ffmpeg_version }}'
shopt -s nullglob

# 1. Our patches, byte for byte, with the same `<sha256>  <name>`
#    manifest the vendor builds write as MESHHARBOR-PATCHES.txt.
mkdir -p bundle/patches
patches=( .github/ffmpeg-patches/*.patch )
for p in "${patches[@]}"; do cp "$p" bundle/patches/; done
# ⚠️ Never `sha256sum *.patch` with nothing to match: under nullglob it
# gets no arguments and hashes STDIN, writing a bogus `…  -` line.
if [ "${#patches[@]}" -gt 0 ]; then
  ( cd bundle/patches && sha256sum *.patch ) > bundle/patches/MESHHARBOR-PATCHES.txt
else
  : > bundle/patches/MESHHARBOR-PATCHES.txt
fi
shipped=( bundle/patches/*.patch )
if [ "${#shipped[@]}" -ne "${#patches[@]}" ]; then
  echo "::error::bundle carries ${#shipped[@]} patch(es) but ${#patches[@]} are committed"; exit 1
fi
echo "meshharbor patches in the bundle: ${#shipped[@]}"; cat bundle/patches/MESHHARBOR-PATCHES.txt

# 2. The vcpkg port the Windows build starts from, at the SAME
#    baseline the recipe pins — read from the recipe, never restated
#    here, so the two cannot drift apart.
BASELINE=$(sed -n "s/^[[:space:]]*\$baseline = '\([0-9a-f]\{40\}\)'.*/\1/p" \
  .github/workflows/vendor-ffmpeg-windows.yml | head -1)
if [ -z "$BASELINE" ]; then
  echo "::error::no \$baseline = '<sha>' found in vendor-ffmpeg-windows.yml — re-derive the parse"; exit 1
fi
mkdir -p bundle/vcpkg-port-ffmpeg
listing=$(gh api "repos/microsoft/vcpkg/contents/ports/ffmpeg?ref=$BASELINE")
# A subdirectory would be skipped by the file loop below. Refuse
# rather than publish a port with a hole in it.
dirs=$(printf '%s' "$listing" | jq '[.[] | select(.type != "file")] | length')
if [ "$dirs" -ne 0 ]; then
  echo "::error::ports/ffmpeg@$BASELINE has $dirs non-file entries — extend the fetch"; exit 1
fi
printf '%s' "$listing" | jq -r '.[] | "\(.name) \(.download_url)"' | while read -r name url; do
  curl -fsSL -o "bundle/vcpkg-port-ffmpeg/$name" "$url"
done
test -f bundle/vcpkg-port-ffmpeg/portfile.cmake \
  || { echo "::error::vcpkg port fetch produced no portfile.cmake"; exit 1; }
echo "$BASELINE" > bundle/vcpkg-port-ffmpeg/VCPKG-BASELINE.txt
echo "vcpkg ports/ffmpeg@$BASELINE: $(ls bundle/vcpkg-port-ffmpeg | wc -l) files"

# 3. What this bundle was built FROM, as its own small asset, so
#    release-agent can check the offer against a checkout without
#    downloading the 17 MB tarball. Same `<hash> <name>` shape as the
#    patch manifest: every patch, the vcpkg baseline, and (FR-85 P4c)
#    the two recipe files the next step ships. The configure options
#    live in the recipe, not in a patch: before this, a build whose
#    options changed (P4a added the h264 decoder and the aac encoder)
#    passed the release gate against an offer describing the old one.
{
  cat bundle/patches/MESHHARBOR-PATCHES.txt
  echo "$BASELINE  vcpkg-baseline"
  for r in vendor-ffmpeg-windows.yml vendor-ffmpeg-macos.yml; do
    printf '%s  recipe/%s\n' "$(sha256sum ".github/workflows/$r" | cut -d' ' -f1)" "$r"
  done
} | sort > "$RUNNER_TEMP/inputs.txt"
echo "inputs:"; cat "$RUNNER_TEMP/inputs.txt"
```


### Archived step: Emit the exact build recipe (original line 133)

```text
set -euo pipefail
V='${{ inputs.ffmpeg_version }}'
shopt -s nullglob
# The vcpkg overlay port is GENERATED at build time by
# vendor-ffmpeg-windows.yml rather than committed, so the workflow
# files themselves are part of the corresponding source. Ship them.
mkdir -p bundle/recipe
cp .github/workflows/vendor-ffmpeg-windows.yml bundle/recipe/
cp .github/workflows/vendor-ffmpeg-macos.yml   bundle/recipe/

BASELINE=$(cat bundle/vcpkg-port-ffmpeg/VCPKG-BASELINE.txt)
ours=( bundle/patches/*.patch )
if [ "${#ours[@]}" -gt 0 ]; then
  OURS_LIST=$(for p in "${ours[@]}"; do printf -- '  * `patches/%s`\n' "$(basename "$p")"; done)
  OURS_SUMMARY="We apply ${#ours[@]} patch(es) of our own, listed below with SHA-256 in \`patches/MESHHARBOR-PATCHES.txt\`."
else
  OURS_LIST="  * (none)"
  OURS_SUMMARY="We apply no patches of our own."
fi
PORT_PATCHES=$(for p in bundle/vcpkg-port-ffmpeg/*.patch; do printf -- '  * `vcpkg-port-ffmpeg/%s`\n' "$(basename "$p")"; done)

cat > bundle/recipe/README.md <<RECIPE
# FFmpeg $V — corresponding source and build recipe

This bundle is published to satisfy LGPL-2.1 §6 for the FFmpeg
libraries distributed with MeshHarbor. It is the upstream source plus
**every change our builds make to it**:

* \`ffmpeg-$V.tar.gz\` — the upstream source, exactly as tagged
  (it unpacks to \`FFmpeg-$V/\`).
* \`patches/\` — our own source patches. $OURS_SUMMARY
$OURS_LIST
* \`vcpkg-port-ffmpeg/\` — the vcpkg \`ffmpeg\` port the Windows build
  starts from, at vcpkg baseline \`$BASELINE\`. Its patches are
  vcpkg's, and the Windows build applies them too:
$PORT_PATCHES
* \`recipe/vendor-ffmpeg-windows.yml\` — the exact workflow that
  produces the Windows (static, MSVC) and Linux (shared) builds,
  including the configure options it injects into the port.
* \`recipe/vendor-ffmpeg-macos.yml\` — the macOS build.

## What each build applies

| Platform | Linkage | Source changes applied | LGPL clause |
|---|---|---|---|
| Windows (\`meshharbord.exe\`) | **static** (\`x64-windows-static-md\`) | our patches, then the vcpkg port's own, in its \`PATCHES\` list | §6: relinking must be possible |
| Linux (\`.deb\`) | shared (\`--enable-shared --disable-static\`) | our patches (\`patch -p1\` from the source root, in file-name order) | §6(b): the shared mechanism satisfies it |
| macOS (\`.pkg\`) | shared (the \`*_videotoolbox\` encoders as dylibs in the app bundle) | none | §6(b): the shared mechanism satisfies it |

Beyond those patches, every build's customisation is its configure
flag set, which selects components rather than changing code.

## Rebuilding

Every build runs entirely from the workflow files above on stock
GitHub-hosted runners. Reproducing them needs no private input:

\`\`\`
gh workflow run vendor-ffmpeg-windows.yml
\`\`\`

To reproduce the Linux tree by hand:

\`\`\`
tar xf ffmpeg-$V.tar.gz && cd FFmpeg-$V
for p in ../patches/*.patch; do patch -p1 < "\$p"; done
# then configure with the flags in recipe/vendor-ffmpeg-windows.yml (Linux job)
\`\`\`

## Relinking the Windows agent

To exercise your §6 rights on the statically-linked Windows build,
request the linkable object files for a specific released version at
**legal@meshharbor.itachi.fans**, quoting the version string from
\`meshharbord.exe --version\`. See THIRD-PARTY-NOTICES.md in the MeshHarbor
repository for the full written offer.
RECIPE
cat bundle/recipe/README.md
```


### Archived step: Pack, checksum, publish (original line 216)

```text
set -euo pipefail
V='${{ inputs.ffmpeg_version }}'
OUT="ffmpeg-$V-corresponding-source.tar.xz"
INPUTS="ffmpeg-$V-corresponding-source.inputs.txt"
tar -C bundle -cJf "$OUT" .
sha256sum "$OUT" > "$OUT.sha256"
cat "$OUT.sha256"
cp "$RUNNER_TEMP/inputs.txt" "$INPUTS"
gh release upload '${{ inputs.release_tag }}' "$OUT" "$OUT.sha256" "$INPUTS" \
  --repo "${{ github.repository }}" --clobber
echo "published $OUT and $INPUTS to ${{ inputs.release_tag }}"
```


### Archived step: Assert the offer resolves (original line 232)

```text
set -euo pipefail
V='${{ inputs.ffmpeg_version }}'
# A written offer pointing at a missing asset is worse than no offer:
# it claims compliance we do not have. Verify the URL the notice
# publishes actually serves bytes.
names=$(gh release view '${{ inputs.release_tag }}' \
  --repo "${{ github.repository }}" --json assets --jq '.assets[].name')
for want in "ffmpeg-$V-corresponding-source.tar.xz" \
            "ffmpeg-$V-corresponding-source.tar.xz.sha256" \
            "ffmpeg-$V-corresponding-source.inputs.txt"; do
  printf '%s\n' "$names" | grep -qx "$want" \
    || { echo "::error::$want missing from the release"; exit 1; }
done
# And that what is served is what was built: download the bundle
# back and check it carries every committed patch.
mkdir -p /tmp/served && cd /tmp/served
gh release download '${{ inputs.release_tag }}' --repo "${{ github.repository }}" \
  --pattern "ffmpeg-$V-corresponding-source.tar.xz*" --clobber
sha256sum -c "ffmpeg-$V-corresponding-source.tar.xz.sha256"
served=$(tar tJf "ffmpeg-$V-corresponding-source.tar.xz" | grep -c '^\./patches/.*\.patch$' || true)
shopt -s nullglob
cp_files=( "$GITHUB_WORKSPACE"/.github/ffmpeg-patches/*.patch )
committed=${#cp_files[@]}
if [ "$served" -ne "$committed" ]; then
  echo "::error::the served bundle carries $served patch(es); $committed are committed"; exit 1
fi
echo "OK: corresponding-source bundle is live on ${{ inputs.release_tag }} with $served patch(es)."
```


## licensing

Original path: `.github/workflows/licensing.yml`; SHA-256: `e8489e25a47822bba3b7757b6e446f526f006750c1039f30b5646f15bf65fa3c`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Every workspace member declares an explicit `license` (original line 63)

```text
set -euo pipefail
source scripts/licence-classes.sh
fail=0
# The WORKSPACE decides what is a member, not a glob. This step used to
# iterate `crates/*/Cargo.toml agents/*/Cargo.toml`, one level deep, so
# when FR-69 put six crates under `crates/modules/` it checked 18 of 24
# members and still printed OK. The six happened to declare AGPL
# correctly; nothing here would have noticed if they had not.
members=$(awk '/^members *= *\[/{p=1; next} p && /^\]/{exit} p' Cargo.toml \
  | sed -E 's/#.*//' | grep -oE '"[^"]+"' | tr -d '"')
n=$(printf '%s\n' "$members" | grep -c . || true)
if [ "$n" -eq 0 ]; then
  echo "::error::parsed no workspace members from Cargo.toml — refusing to report a clean split"
  exit 1
fi
for m in $members; do
  f="$m/Cargo.toml"
  pkg=$(grep -m1 '^name = ' "$f" | sed 's/name = //;s/"//g')
  # Only the [package] section counts — [package.metadata.wix] also
  # has a `license` key, and it means something entirely different.
  got=$(awk '/^\[/{n++} n>1{exit} /^license = /{print $3}' "$f" | tr -d '"')
  want=$(licence_for_crate "$pkg") || {
    echo "::error file=$f::$pkg is not classified in scripts/licence-classes.sh"
    fail=1; continue
  }
  if [ "$got" != "$want" ]; then
    echo "::error file=$f::$pkg declares '${got:-<none>}', expected '$want'"
    fail=1
  fi
done
[ "$fail" = 0 ] && echo "OK: all $n workspace members declare the expected licence."
exit $fail
```


### Archived step: Every first-party source file carries the right SPDX header (original line 98)

```text
bash scripts/apply-spdx.sh --check
```


### Archived step: No AGPL crate reaches a shipped agent binary (original line 107)

```text
set -euo pipefail
source scripts/licence-classes.sh
fail=0
for agent in "${SHIPPED_AGENT_CRATES[@]}"; do
  # -e normal drops dev-dependencies: a test-only edge cannot reach a
  # shipped binary, and treating it as a violation would be a false
  # positive that trains people to disable this check.
  graph=$(cargo tree -p "$agent" -e normal --prefix none --no-dedupe 2>/dev/null | awk '{print $1}' | sort -u)
  for server in "${SERVER_CRATES[@]}"; do
    if printf '%s\n' "$graph" | grep -qx "$server"; then
      echo "::error::$agent (MPL-2.0, shipped to customer machines) depends on $server ($SERVER_LICENCE)."
      echo "         This would make the agent effectively $SERVER_LICENCE. See LICENSING.md."
      cargo tree -p "$agent" -e normal --invert "$server" 2>/dev/null | head -20
      fail=1
    fi
  done
done
[ "$fail" = 0 ] && echo "OK: no $SERVER_LICENCE crate reaches any shipped agent binary."
exit $fail
```


## ci

Original path: `.github/workflows/ci.yml`; SHA-256: `07c9a98d514972585740fd4f061271484df4e5ac0688f0088b81d1bf7cf1868d`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Check formatting (original line 166)

```text
cargo fmt --check --all
```


### Archived step: Assert the icons are real (original line 186)

```text
python3 - <<'PY'
import sys, struct, pathlib

bad = []

def check_png(p, min_px):
    raw = p.read_bytes()
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        bad.append(f"{p}: not a PNG"); return
    # IHDR is always the first chunk: width/height at bytes 16..24.
    w, h = struct.unpack(">II", raw[16:24])
    if min(w, h) < min_px:
        bad.append(f"{p}: {w}x{h} — a placeholder, not an icon (need >= {min_px} px)")

def check_ico(p):
    raw = p.read_bytes()
    # ICONDIR: reserved u16 (0), type u16 (1 = icon), count u16; then
    # 16-byte ICONDIRENTRYs whose first byte is the width (0 == 256).
    if len(raw) < 6 or struct.unpack("<HH", raw[:4]) != (0, 1):
        bad.append(f"{p}: not an ICO"); return
    count = struct.unpack("<H", raw[4:6])[0]
    widths = [raw[6 + 16 * i] for i in range(count) if 6 + 16 * i < len(raw)]
    if count < 5:
        bad.append(f"{p}: {count} entries — a placeholder, not an icon set (need >= 5)")
    if 0 not in widths:
        bad.append(f"{p}: no 256 px entry (widths {widths})")
    if len(raw) <= 4096:
        bad.append(f"{p}: {len(raw)} bytes — a placeholder, not an icon set (need > 4 KiB)")

desktop = pathlib.Path("agents/meshharbor-desktop/icons")
check_png(desktop / "tray.png", 16)
# FR-85 — the tray while a recording runs (tray.rs swaps it in).
check_png(desktop / "tray-recording.png", 16)
check_png(desktop / "icon.png", 128)
check_ico(desktop / "icon.ico")

setup = pathlib.Path("agents/meshharbor-setup/icons")
check_png(setup / "icon.png", 128)
check_ico(setup / "icon.ico")

if bad:
    print("::error::" + "; ".join(bad))
    print("regenerate with: python3 scripts/gen-tray-icons.py [--target setup]")
    sys.exit(1)
print("  companion + wizard icons OK")
PY
```


### Archived step: Vendored webrtc-ice drift check (original line 239)

```text
bash scripts/revendor-webrtc-ice.sh --check
```


### Archived step: Vendored wintun-bindings drift check (original line 244)

```text
bash scripts/revendor-wintun-bindings.sh --check
```


### Archived step: Vendored scrap drift check (original line 250)

```text
bash scripts/revendor-scrap.sh --check
```


### Archived step: Vendored webrtc-sctp drift check (original line 255)

```text
bash scripts/revendor-webrtc-sctp.sh --check
```


### Archived step: Vendored smoltcp drift check (original line 260)

```text
bash scripts/revendor-smoltcp.sh --check
```


### Archived step: Run clippy (original line 271)

```text
cargo clippy --workspace -- -D warnings
```


### Archived step: Run clippy on the X11 consent panel (original line 278)

```text
cargo clippy -p meshharbord --lib --features viewer-indicator-x11 -- -D warnings
```


### Archived step: Run clippy on the audited crates (incl. test targets) (original line 307)

```text
cargo clippy -p meshharbor-api -p meshharbor-services -p meshharbor-tests -p meshharbor-core --all-targets -- -D warnings
```


### Archived step: Type-check the integration test crate (original line 326)

```text
cargo check -p meshharbor-tests --all-targets
```


### Archived step: Clippy agent --features full (the capture + encode + input path) (original line 359)

```text
cargo clippy -p meshharbord --features full,vp9-444,vp9-444-bindgen,clipboard,ssh-server,recording,hive,vault --all-targets -- -D warnings -A dead_code
```


### Archived step: Clippy tunnel-core --features overlay-l3,overlay-netstack (original line 376)

```text
cargo clippy -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --all-targets -- -D warnings
```


### Archived step: Clippy meshharbord --features overlay-l3 (original line 382)

```text
cargo clippy -p meshharbord --features overlay-l3 -- -D warnings
```


### Archived step: Run API unit tests (original line 431)

```text
cargo test -p meshharbor-api --lib
```


### Archived step: Run core unit tests (original line 441)

```text
cargo test -p meshharbor-core --lib
```


### Archived step: Run fleet module unit tests (original line 446)

```text
cargo test -p meshharbor-mod-fleet --lib
```


### Archived step: Run the remaining crates' unit tests (original line 475)

```text
cargo test --lib
-p meshharbor-remote-control -p meshharbor-mod-network
-p meshharbor-node-core -p meshharbor-cli -p meshharbor-localapi
-p meshharbor-services -p meshharbor-db -p meshharbor-config
-p meshharbor-mod-chat -p meshharbor-mod-saas
-p tcp-turn-conn -p meshharbor-setup-core -p meshharbor-setup
-p meshharbor-hive-node -p meshharbor-mod-hive -p meshharbor-mod-remote
-p meshharbor-mod-vault
```


### Archived step: Run the PoP relay's tests (original line 492)

```text
cargo test -p derp-relay --bins
```


### Archived step: Test the desktop companion (meshharbor-desktop) (original line 504)

```text
cargo test -p meshharbor-desktop --bins
```


### Archived step: Check agent --features vp9-444 (original line 545)

```text
cargo check -p meshharbord --features vp9-444,vp9-444-bindgen
```


### Archived step: Test agent under vp9-444 (original line 609)

```text
cargo test -p meshharbord --features vp9-444,vp9-444-bindgen,clipboard,ssh-server,hive,vault,portal-capture,drm-capture,uinput-input,enigo-input,external-access --lib
```


### Archived step: Test tunnel-core --features overlay-l3,overlay-netstack (original line 620)

```text
cargo test -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --lib -- --test-threads=1
```


### Archived step: Test the tunnel CLI (meshharbor-cli --lib) (original line 628)

```text
cargo test -p meshharbor-cli --lib
```


### Archived step: Multi-org shared TUN against real kernel networking (original line 643)

```text
sudo modprobe tun || true
# Build FIRST with human diagnostics. The json pass below would
# otherwise swallow a compile error into records jq drops, leaving
# only an empty $BIN and "sudo: : command not found".
cargo test -p meshharbord --features overlay-l3 --lib --no-run
BIN=$(cargo test -p meshharbord --features overlay-l3 --lib \
        --no-run --message-format=json \
      | jq -r 'select(.profile.test == true) | .executable' | head -1)
echo "test binary: $BIN"
sudo MESHHARBOR_TUN_KERNEL_TEST=1 "$BIN" tun_kernel_tests \
  --test-threads=1 --nocapture
```


### Archived step: DERP dialer — unit tests (#2512) (original line 666)

```text
cargo test -p meshharbord --features overlay-l3 --lib -- derp:: > derp-tests.txt 2>&1 \
  || { cat derp-tests.txt; exit 1; }
cat derp-tests.txt
grep -E 'test result: ok\. [1-9][0-9]* passed' derp-tests.txt
```


### Archived step: Test the recorder (FR-85) — unit tests + the recorder integration binary (original line 756)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --lib recording::
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test recorder
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test control_dc_record
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test export
```


### Archived step: The privacy channel (FR-99 P1b) — the production handler over a loopback pair (original line 770)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test privacy_dc
```


### Archived step: A DataChannel session answers an offer without H.264 (#2231) (original line 780)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test dc_track_codec
```


### Archived step: L0 latency harness (FR-16) — capture → decode on one clock, over a vnet (original line 793)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --lib capture::synthetic_backend
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test l4_latency -- --nocapture
```


### Archived step: Linux recorder identity (FR-85) — as root, the drop and the thread's filesystem identity (original line 804)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --lib --no-run --message-format=json > /tmp/p1eu.json
BIN=$(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' /tmp/p1eu.json | head -1)
if [ -z "$BIN" ]; then echo "::error::no meshharbord lib test binary in the build output"; exit 1; fi
sudo MESHHARBORD_TEST_REQUIRE_ROOT=1 "$BIN" recording::launch
```


### Archived step: The tarball repair, as root — another account's tree comes back root's, and no symlink is followed (original line 816)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --lib --no-run --message-format=json > /tmp/tob.json
BIN=$(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' /tmp/tob.json | head -1)
if [ -z "$BIN" ]; then echo "::error::no meshharbord lib test binary in the build output"; exit 1; fi
sudo MESHHARBORD_TEST_REQUIRE_ROOT=1 "$BIN" tarball_owner
```


### Archived step: Received files on a Linux system install (FR-97 P3d) — as root, born the person's (original line 829)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --lib --no-run --message-format=json > /tmp/p3d.json
BIN=$(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' /tmp/p3d.json | head -1)
if [ -z "$BIN" ]; then echo "::error::no meshharbord lib test binary in the build output"; exit 1; fi
sudo MESHHARBORD_TEST_REQUIRE_ROOT=1 "$BIN" files::seat_user_tests
```


### Archived step: The Linux user unit's sandbox (FR-85 P2c) — it starts on a fresh host, and the recorder writes ~/Videos (original line 854)

```text
set -eu
cargo build -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --message-format=json > /tmp/p2c-build.json
BIN=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "meshharbord" and .executable != null) | .executable' /tmp/p2c-build.json | tail -1)
if [ -z "$BIN" ]; then echo "::error::no meshharbord binary in the build output"; exit 1; fi
ME=$(id -un)
H=$(getent passwd "$ME" | cut -d: -f6)
# What `meshharbord enroll` leaves behind, and an XDG Videos folder.
mkdir -p "$H/.config/meshharbor" "$H/.local/share/meshharbor" "$H/Videos"
printf 'XDG_VIDEOS_DIR="$HOME/Videos"\n' > "$H/.config/user-dirs.dirs"
# Every path the unit lists as optional (`-`), the XDG user folders
# (~/Videos, ~/Downloads) aside, must be MISSING, as on any host
# installed after the rename, or the cell proves nothing about a
# missing path. /var/tmp is aside too: it exists on every Linux
# host, its `-` is belt and braces, and what FR-96 P2a needs from it
# is that the sandbox leaves it WRITABLE — asserted below, with a
# negative control.
for p in $(grep -E '^ReadWritePaths=' agents/meshharbord/packaging/linux/meshharbor.service | sed 's/^ReadWritePaths=//' | tr ' ' '\n' | grep '^-' | sed "s|^-||; s|%h|$H|g"); do
  if [ "$p" != "$H/Videos" ] && [ "$p" != "$H/Downloads" ] && [ "$p" != /var/tmp ] && [ -e "$p" ]; then echo "::error::$p exists on the runner; the cell proves nothing"; exit 1; fi
done
OUT=/tmp/p2c-where.out
# Can the unit create a file in /var/tmp? Used by both units below.
# No `%` or `$` in it: systemd would expand either in ExecStart.
WAKE_PROBE='if touch /var/tmp/.p2c-wake-probe 2>/dev/null; then echo VARTMP_WRITABLE; rm -f /var/tmp/.p2c-wake-probe; else echo VARTMP_READ_ONLY; fi'
{
  echo "[Service]"
  echo "Type=oneshot"
  echo "User=$ME"
  echo "StandardOutput=file:$OUT"
  echo "StandardError=journal"
  echo "ExecStart=/bin/sh -c '\"$BIN\" record --where; if touch \"$H/.p2c-probe\" 2>/dev/null; then echo HOME_WRITABLE; else echo HOME_READ_ONLY; fi; $WAKE_PROBE'"
  grep -E '^(NoNewPrivileges|ProtectSystem|ProtectHome|ReadWritePaths)=' agents/meshharbord/packaging/linux/meshharbor.service | sed "s|%h|$H|g"
} | sudo tee /etc/systemd/system/p2c-sandbox.service
sudo systemctl daemon-reload
if ! sudo systemctl start p2c-sandbox.service; then
  sudo journalctl -u p2c-sandbox.service --no-pager | tail -20
  echo "::error::a unit carrying meshharbor.service's sandbox did not start"; exit 1
fi
cat "$OUT"
grep -q "$H/Videos/MeshHarbor" "$OUT" || { echo "::error::under the sandbox the recorder did not choose ~/Videos/MeshHarbor"; exit 1; }
grep -q HOME_READ_ONLY "$OUT" || { echo "::error::the sandbox left the rest of home writable"; exit 1; }
# FR-96 P2a: a per-user daemon whose host has the root update
# helper touches its wake file, /var/tmp/meshharbor-update-check.
# ProtectSystem=strict leaves /var/tmp read-only (measured on
# Fedora 44 KDE: EROFS), so the unit grants it.
grep -q VARTMP_WRITABLE "$OUT" || { echo "::error::under the sandbox the daemon cannot write /var/tmp — FR-96's wake file would fail EROFS"; exit 1; }
# The negative control: the same sandbox WITHOUT that grant must
# leave /var/tmp read-only, or the probe cannot tell the two apart
# and the check above proves nothing.
NC=/tmp/p2c-nogrant.out
{
  echo "[Service]"
  echo "Type=oneshot"
  echo "User=$ME"
  echo "StandardOutput=file:$NC"
  echo "StandardError=journal"
  echo "ExecStart=/bin/sh -c '$WAKE_PROBE'"
  grep -E '^(NoNewPrivileges|ProtectSystem|ProtectHome|ReadWritePaths)=' agents/meshharbord/packaging/linux/meshharbor.service | grep -vx 'ReadWritePaths=-/var/tmp' | sed "s|%h|$H|g"
} | sudo tee /etc/systemd/system/p2c-nogrant.service
if grep -q '^ReadWritePaths=.*/var/tmp' /etc/systemd/system/p2c-nogrant.service; then echo "::error::the negative control still grants /var/tmp"; exit 1; fi
sudo systemctl daemon-reload
if ! sudo systemctl start p2c-nogrant.service; then
  sudo journalctl -u p2c-nogrant.service --no-pager | tail -20
  echo "::error::the negative control's unit did not start"; exit 1
fi
cat "$NC"
grep -q VARTMP_READ_ONLY "$NC" || { echo "::error::without its grant the sandbox still let the unit write /var/tmp: the probe cannot tell, so the check above proves nothing"; exit 1; }
```


### Archived step: The Linux user unit runs where its user manager sandboxes it — Fedora's configuration (#1997) (original line 936)

```text
set -eu
cargo build -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --message-format=json > /tmp/uu-build.json
BIN=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "meshharbord" and .executable != null) | .executable' /tmp/uu-build.json | tail -1)
if [ -z "$BIN" ]; then echo "::error::no meshharbord binary in the build output"; exit 1; fi
ME=$(id -un)
MYUID=$(id -u)
H=$(getent passwd "$ME" | cut -d: -f6)
RUN=/run/user/$MYUID
export XDG_RUNTIME_DIR=$RUN
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
sudo loginctl enable-linger "$ME"
for _ in $(seq 1 30); do [ -S "$RUN/systemd/private" ] && break; sleep 1; done
[ -S "$RUN/systemd/private" ] || { echo "::error::no user manager for $ME"; exit 1; }
# What `meshharbord enroll` leaves behind, for a server nobody answers:
# the daemon takes its lock and binds LocalAPI before it needs one.
mkdir -p "$H/.config/meshharbor" "$H/.local/share/meshharbor" "$H/.config/systemd/user"
printf '%s\n' 'server_url = "http://127.0.0.1:9"' 'agent_token = "ci"' \
  'agent_id = "000000000000000000000000"' 'tenant_id = "000000000000000000000000"' \
  'machine_id = "ci"' 'machine_name = "ci"' > "$H/.config/meshharbor/config.toml"
sed "s|^ExecStart=.*|ExecStart=$BIN run|" agents/meshharbord/packaging/linux/meshharbor.service > "$H/.config/systemd/user/meshharbor.service"
systemctl --user daemon-reload
systemctl --user start meshharbor.service
sock=""
for _ in $(seq 1 45); do [ -S "$RUN/meshharbor.sock" ] && { sock=1; break; }; sleep 1; done
show_log() { sudo journalctl "_UID=$MYUID" _SYSTEMD_USER_UNIT=meshharbor.service --no-pager -n 25 || true; }
PID=$(systemctl --user show -p MainPID --value meshharbor.service)
case "$PID" in ''|0) show_log; echo "::error::the unit has no running daemon"; exit 1 ;; esac
[ "$(sudo readlink "/proc/$PID/ns/mnt")" != "$(sudo readlink /proc/1/ns/mnt)" ] \
  || { echo "::error::the unit ran in the host's mount namespace: its sandbox did not apply, and this cell proves nothing"; exit 1; }
[ -n "$sock" ] || { show_log; echo "::error::no LocalAPI socket at $RUN/meshharbor.sock within 45 s"; exit 1; }
opts() { sudo awk -v p="$1" '$5 == p { o = $6 } END { print o }' "/proc/$PID/mountinfo"; }
# The mount that governs a path: the longest mount point containing
# it. /home is often not a mount of its own, and then ProtectSystem's
# read-only / is the one.
governing() {
  sudo awk -v p="$1" '{ m = $5; ok = (m == "/" || p == m || index(p, m "/") == 1) } ok && length(m) >= best { best = length(m); o = $6 } END { print o }' "/proc/$PID/mountinfo"
}
# /var/tmp: FR-96 P2a's wake file for the root update helper.
# Measured on Fedora 44 KDE, the field configuration this cell
# reproduces: 0.4.128's unit left it read-only (EROFS) in the
# daemon's namespace; the grant makes it a read-write mount of its own.
for p in "$RUN" "$H/.local/state/meshharbor" "$H/.config/meshharbor" "$H/.local/share/meshharbor" /var/tmp; do
  case "$(opts "$p")" in
    rw*) ;;
    *) echo "::error::$p is not writable inside the unit (mount options '$(opts "$p")')"; sudo awk '{ print $5, $6 }' "/proc/$PID/mountinfo" | grep -E "^($H|/run/user|/var/tmp)"; exit 1 ;;
  esac
done
case "$(governing "$H")" in ro*) ;; *) echo "::error::$H is writable inside the unit ('$(governing "$H")')"; exit 1 ;; esac
echo "the user unit: sandboxed, LocalAPI bound, the runtime, state, config and data folders and /var/tmp writable, the rest of home read-only"
systemctl --user stop meshharbor.service
```


### Archived step: Test the recorder WITH audio (FR-85 P1c, P5b) — unit tests + the recorder integration binary (original line 1029)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source,audio --lib recording::
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source,audio --test recorder
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source,audio --test export
```


### Archived step: The recorder's pointer (FR-85 P1d) and keep busy (FR-92 P3) on X11 — against a real X server (original line 1088)

```text
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends xvfb xauth
xvfb-run -a -s "-screen 0 1280x1024x24 -noreset" env MESHHARBORD_TEST_X11=1 cargo test -p meshharbord --features scrap-capture,enigo-input,viewer-indicator-x11,clipboard --lib -- capture::pointer capture::x11_cursor keep_busy::host_x11 capture::xwayland_probe_tests indicator::x11 input::layout_x11 clipboard::x11_gate_tests --nocapture --test-threads=1 | tee /tmp/x11-tests.log
grep -q "x11-real: XTest motion reset the idle counter" /tmp/x11-tests.log
grep -q "x11-real: ran with idle" /tmp/x11-tests.log
grep -q "x11-real: Xvfb does not advertise XWAYLAND" /tmp/x11-tests.log
grep -q "x11-real: an XWAYLAND monitor reads as Xwayland" /tmp/x11-tests.log
grep -q "x11-real: a dismissed prompt left the screen" /tmp/x11-tests.log
grep -q "x11-real: the X11 pointer reached the cursor channel" /tmp/x11-tests.log
grep -q "x11-real: the layouts .* read back, and the switch to de-DE and back took" /tmp/x11-tests.log
grep -q "x11-real: the clipboard gate counted an owner change" /tmp/x11-tests.log
```


### Archived step: Every Rust lane succeeded (original line 1116)

```text
echo "$NEEDS" | jq -r 'to_entries[] | "\(.key): \(.value.result)"'
bad=$(echo "$NEEDS" | jq -r '[to_entries[] | select(.value.result != "success") | .key] | join(" ")')
if [ -n "$bad" ]; then
  echo "::error::Rust lanes that did not succeed: $bad"
  exit 1
fi
```


### Archived step: Install Rust toolchain (original line 1151)

```text
rustup show active-toolchain || rustup toolchain install
```


### Archived step: cargo check tunnel-core (overlay-l3 + overlay-netstack) (original line 1168)

```text
cargo check -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack
```


### Archived step: cargo check agent (ssh-server — the raw-libc surface) (original line 1184)

```text
cargo check -p meshharbord --lib --features ssh-server
```


### Archived step: cargo check agent (scrap-capture — the macOS capture surface) (original line 1193)

```text
cargo check -p meshharbord --lib --features scrap-capture
```


### Archived step: cargo check agent (viewer-indicator-macos — the AppKit panel + the main-thread swap) (original line 1201)

```text
cargo check -p meshharbord --lib --bins --features viewer-indicator-macos
```


### Archived step: cargo check agent BINARY (macOS cfg arms in main.rs) (original line 1211)

```text
cargo check -p meshharbord --bins --features scrap-capture
```


### Archived step: cargo check + test agent sessions on macOS (FR-90 P1h — `hive`) (original line 1225)

```text
cargo check -p meshharbord --lib --bins --features hive,vault
cargo test -p meshharbord --lib --features hive,vault -- hive:: vault:: vault_proxy:: macos_supervisor::
```


### Archived step: cargo check agent with the release feature set (FR-85 — `full`, recording included) (original line 1242)

```text
cargo check -p meshharbord --lib --bins --features full,recording
```


### Archived step: cargo check the desktop companion (original line 1249)

```text
cargo check -p meshharbor-desktop
```


### Archived step: Lint the macOS packaging (original line 1255)

```text
set -euo pipefail
for p in agents/meshharbord/packaging/macos/*.plist; do
  plutil -lint "$p"
done
bash -n agents/meshharbord/packaging/macos/postinstall
# The daemon plist must point at a path the .pkg actually creates,
# and must NOT reuse the LaunchAgent's Label — launchctl would
# refuse the second bootstrap and the failure reads as "already
# loaded" rather than "you shipped one label twice".
# Every launchd job this package installs must have a DISTINCT Label:
# launchctl refuses the second bootstrap of a duplicate and the error
# reads "already loaded" rather than "you shipped one label twice".
#
# Globbed on `fans.itachi.meshharbor.*` — the launchd jobs — rather than every
# .plist in the directory, which also holds entitlements.plist (a
# codesign input with no Label at all).
labels=$(for p in agents/meshharbord/packaging/macos/fans.itachi.meshharbor.*.plist; do
           plutil -extract Label raw "$p" \
             || { echo "::error::$p has no Label"; exit 1; }
         done)
echo "$labels" | sed 's/^/  label: /'
# agent + daemon + desktop. A lower count means a job stopped being
# globbed, which would silently make the duplicate check vacuous.
count=$(echo "$labels" | grep -c .)
[ "$count" -ge 3 ] || { echo "::error::expected >=3 launchd jobs, found $count"; exit 1; }
dupes=$(echo "$labels" | sort | uniq -d)
[ -z "$dupes" ] || { echo "::error::duplicate launchd Label(s): $dupes"; exit 1; }
# FR-46 P5b — the daemon plist must point INSIDE the bundle, at the
# renamed executable. This assert is why a half-done rename cannot ship:
# a plist still naming the old path installs fine and the daemon simply
# never starts, which reads as "the overlay is down", not as a typo.
grep -q '/Library/MeshHarbor/meshharbord.app/Contents/MacOS/meshharbord' \
  agents/meshharbord/packaging/macos/fans.itachi.meshharbor.daemon.plist
```


### Archived step: macOS overlay against a real utun (original line 1300)

```text
BIN=$(cargo test -p meshharbor-tunnel-core --features overlay-l3 --lib \
        --no-run --message-format=json \
      | jq -r 'select(.profile.test == true) | .executable' | head -1)
echo "test binary: $BIN"
sudo MESHHARBOR_TUN_KERNEL_TEST=1 "$BIN" macos_kernel_tests \
  --test-threads=1 --nocapture
```


### Archived step: Clippy tunnel-core (overlay-l3 + overlay-netstack, all targets) (original line 1362)

```text
cargo clippy -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --all-targets -- -D warnings
```


### Archived step: Clippy meshharbord (overlay-l3 + ssh-server + hive, incl. tests) (original line 1374)

```text
cargo clippy -p meshharbord --features overlay-l3,ssh-server,hive,vault --tests -- -D warnings
```


### Archived step: LocalAPI on Windows — clippy + unit tests (FR-92 P10b) (original line 1383)

```text
cargo clippy -p meshharbor-localapi --all-targets -- -D warnings
cargo test -p meshharbor-localapi --lib
```


### Archived step: Agent sessions on Windows — unit tests (FR-90 P1i) (original line 1408)

```text
cargo test -p meshharbord --lib --features overlay-l3,ssh-server,hive,vault -- hive:: hive_win win_service::supervisor win_service::tests win_service::orphan vault:: vault_proxy:: ssh_service::
```


### Archived step: The overlay and the privacy curtain — clippy + unit tests (FR-99 P1b) (original line 1419)

```text
cargo clippy -p meshharbord --lib --features viewer-indicator -- -D warnings
cargo test -p meshharbord --lib --features viewer-indicator -- privacy:: indicator::
```


### Archived step: Clippy meshharbord (recording, incl. tests) (original line 1481)

```text
cargo clippy -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --tests -- -D warnings
```


### Archived step: The identity rule — unit tests (the table, argv, env, impersonation) (original line 1483)

```text
cargo test -p meshharbord --lib --features recording,openh264-encoder,synthetic-frame-source -- recording::launch --nocapture
```


### Archived step: The installer's SystemContext record — unit tests (#1727) (original line 1491)

```text
cargo test -p meshharbord --lib --features recording,openh264-encoder,synthetic-frame-source -- win_service::system_context_attempt --nocapture
```


### Archived step: The identity rule — the recorder launched as the person, end to end (original line 1497)

```text
cargo test -p meshharbord --features recording,openh264-encoder,synthetic-frame-source --test recorder -- process::an_elevated process::the_manager_records_as_the_person --nocapture
```


### Archived step: The recorder's pointer — Windows capture compiles, lints, and its units pass (original line 1506)

```text
cargo clippy -p meshharbord --features recording,openh264-encoder,wgc-capture,mf-encoder,scrap-capture --tests -- -D warnings
cargo test -p meshharbord --lib --features recording,openh264-encoder,wgc-capture,mf-encoder,scrap-capture -- capture::pointer capture::wgc_backend::tests::only_a_recording_or_the_escape_hatch_bakes_the_pointer
```


### Archived step: Configure apt retries and refresh the index (original line 1567)

```text
echo 'Acquire::Retries "3";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries
sudo apt-get update -qq
```


### Archived step: Verify libvpx really landed (fallback to apt-get) (original line 1589)

```text
sudo ldconfig
if ! ldconfig -p | grep -q 'libvpx\.so'; then
  echo "::warning::cached apt set did not deliver libvpx — installing directly"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends pkg-config libclang-dev libvpx-dev
fi
ldconfig -p | grep 'libvpx\.so' || { echo "::error::libvpx.so still not loadable after the fallback install"; exit 1; }
```


### Archived step: Fetch vendored FFmpeg 9.0.1 (original line 1600)

```text
set -euo pipefail
# The SAME artifact release-agent.yml consumes, so this lane and the
# tag build cannot disagree about what "the FFmpeg backend" compiles
# against. Minimal build: exactly the ten encoders the cascade
# dispatches, whole lib dir ~2.5 MB.
gh release download vendored-ffmpeg-9.0.1 \
  --repo "${{ github.repository }}" \
  --pattern 'ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz' \
  --dir /tmp/ffdl
sudo mkdir -p /opt/meshharbor-ffmpeg
sudo tar xf /tmp/ffdl/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz \
  -C /opt/meshharbor-ffmpeg --strip-components=1
# The .pc files hardcode the vendor machine's prefix.
sudo sed -i "s|^prefix=.*|prefix=/opt/meshharbor-ffmpeg|" \
  /opt/meshharbor-ffmpeg/lib/pkgconfig/*.pc
{
  echo "FFMPEG_DIR=/opt/meshharbor-ffmpeg"
  echo "PKG_CONFIG_PATH=/opt/meshharbor-ffmpeg/lib/pkgconfig"
  echo "LD_LIBRARY_PATH=/opt/meshharbor-ffmpeg/lib"
} >> "$GITHUB_ENV"
```


### Archived step: Prove pkg-config resolved the VENDORED tree (original line 1627)

```text
set -euo pipefail
prefix=$(pkg-config --variable=prefix libavcodec)
echo "libavcodec $(pkg-config --modversion libavcodec) from $prefix"
if [ "$prefix" != "/opt/meshharbor-ffmpeg" ]; then
  echo "::error::pkg-config resolved libavcodec to '$prefix', not the vendored tree — this lane would be testing the wrong library"
  exit 1
fi
```


### Archived step: Clippy agent --features ffmpeg-encoder + vp9-444 (incl. tests) (original line 1653)

```text
cargo clippy -p meshharbord --features ffmpeg-encoder,vp9-444,vp9-444-bindgen --all-targets -- -D warnings
```


### Archived step: Test agent --features ffmpeg-encoder (original line 1662)

```text
cargo test -p meshharbord --features ffmpeg-encoder --lib
```


### Archived step: Configure apt retries and refresh the index (original line 1710)

```text
echo 'Acquire::Retries "3";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries
sudo apt-get update -qq
```


### Archived step: Install build deps (original line 1719)

```text
sudo apt-get install -y --no-install-recommends pkg-config libclang-dev libasound2-dev cmake libvpx-dev
```


### Archived step: Fetch the vendored FFmpeg with the AAC encoder + H.264 decoder (original line 1723)

```text
set -euo pipefail
gh release download vendored-ffmpeg-9.0.1 \
  --repo "${{ github.repository }}" \
  --pattern 'ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz' \
  --dir /tmp/ffdl
sudo mkdir -p /opt/meshharbor-ffmpeg
sudo tar xf /tmp/ffdl/ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz \
  -C /opt/meshharbor-ffmpeg --strip-components=1
# The .pc files hardcode the vendor machine's prefix.
sudo sed -i "s|^prefix=.*|prefix=/opt/meshharbor-ffmpeg|" \
  /opt/meshharbor-ffmpeg/lib/pkgconfig/*.pc
{
  echo "FFMPEG_DIR=/opt/meshharbor-ffmpeg"
  echo "PKG_CONFIG_PATH=/opt/meshharbor-ffmpeg/lib/pkgconfig"
  echo "LD_LIBRARY_PATH=/opt/meshharbor-ffmpeg/lib"
} >> "$GITHUB_ENV"
```


### Archived step: Prove pkg-config resolved the VENDORED tree (original line 1741)

```text
set -euo pipefail
prefix=$(pkg-config --variable=prefix libavcodec)
echo "libavcodec $(pkg-config --modversion libavcodec) from $prefix"
if [ "$prefix" != "/opt/meshharbor-ffmpeg" ]; then
  echo "::error::pkg-config resolved libavcodec to '$prefix', not the vendored tree — this lane would be testing the wrong library"
  exit 1
fi
```


### Archived step: Clippy the recorder with FFmpeg (incl. tests) (original line 1750)

```text
cargo clippy -p meshharbord --features "$REC_FEATURES" --all-targets -- -D warnings
```


### Archived step: The recorder and the export record AAC and edit hardware recordings — never a quiet fallback (original line 1766)

```text
cargo test -p meshharbord --features "$REC_FEATURES" --lib recording::
cargo test -p meshharbord --features "$REC_FEATURES" --test recorder
cargo test -p meshharbord --features "$REC_FEATURES" --test export
```


### Archived step: Audit the FR registry (original line 1794)

```text
bash scripts/fr-registry-audit.sh
```


### Archived step: Audit anchor ranges (original line 1810)

```text
bash scripts/anchor-range-audit.sh
```


### Archived step: Audit mermaid sequence diagrams (original line 1826)

```text
bash scripts/mermaid-sequence-audit.sh
```


### Archived step: Guard self-test, then scan (original line 1855)

```text
# The selftest plants a canary of every shape IN BOTH CASINGS and
# asserts the guard FAILS, then asserts it passes on the real tree.
# It runs first because this guard has silently self-disarmed four
# times and every symptom was a confident "none found" — most
# recently by matching uppercase only, while the leak that got
# through was written in lowercase.
bash .claude/skills/sanitize-hostnames/selftest.sh
python3 .claude/skills/sanitize-hostnames/check_shapes.py --root .
```


### Archived step: Guard self-tests, then scan the commits this PR adds (original line 1920)

```text
# Selftests first, and both of them: a guard nobody has watched FAIL
# is not evidence of anything. The sibling shape guard has silently
# self-disarmed four times and every symptom was a confident pass.
bash .githooks/check-identity-selftest.sh
bash .claude/hooks/gh-account-guard-selftest.sh

if [ "${{ github.event_name }}" = "pull_request" ]; then
  # ⚠️ A history rewrite (the sanitize-hostnames sweep) force-pushes
  # master and every open PR's head together, and the synchronize
  # event that fires for a PR can still name the PRE-rewrite base,
  # which no longer exists. `git log A..B` against a missing A is an
  # error (exit 20), not a pass: measured 2026-10-21 on two open
  # PRs. The fork point on the CURRENT base branch selects the same
  # commits, so fall back to it -- the PR twin of the push path's
  # missing-BEFORE fallback below.
  BASE="${{ github.event.pull_request.base.sha }}"
  HEAD_SHA="${{ github.event.pull_request.head.sha }}"
  if ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
    BASE=$(git merge-base "origin/${{ github.event.pull_request.base.ref }}" "$HEAD_SHA")
  fi
  RANGE="$BASE..$HEAD_SHA"
else
  # A push to master. `github.event.before` is the zero sha for the
  # first push to a new branch and for a force-push over a deleted
  # ref; fall back to the single head commit rather than scanning
  # nothing or the whole history.
  BEFORE="${{ github.event.before }}"
  if [ -z "$BEFORE" ] || [ "$BEFORE" = "0000000000000000000000000000000000000000" ] \
     || ! git cat-file -e "$BEFORE^{commit}" 2>/dev/null; then
    RANGE="${{ github.sha }}~1..${{ github.sha }}"
  else
    RANGE="$BEFORE..${{ github.sha }}"
  fi
fi
echo "range: $RANGE"
bash .githooks/check-identity.sh --require-commits --range "$RANGE"
```


### Archived step: Audit retired product names (original line 2000)

```text
bash scripts/name-audit.sh --check --strict
```


### Archived step: Report (always, so a red run shows WHAT moved) (original line 2003)

```text
bash scripts/name-audit.sh --summary
```


### Archived step: Install dependencies (original line 2038)

```text
cd ui && bun install --frozen-lockfile
```


### Archived step: Build (includes vue-tsc --noEmit) (original line 2048)

```text
cd ui
echo "bun $(bun --version)"

echo "::group::vue-tsc --noEmit"
bun x vue-tsc --noEmit 2>&1 | tee /tmp/vue-tsc.log
tsc_rc=${PIPESTATUS[0]}
echo "::endgroup::"
if [ "$tsc_rc" != 0 ]; then
  {
    echo "### vue-tsc --noEmit (exit $tsc_rc)"
    echo '```'
    cat /tmp/vue-tsc.log
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
  # Emit last 30 lines of tsc output as a single error
  # annotation. %0A escapes newlines per GHA workflow command
  # grammar so the annotation preserves multi-line output.
  tail -30 /tmp/vue-tsc.log | awk 'BEGIN{ORS="%0A"}{print}' | sed 's/^/::error::vue-tsc: /'
  exit "$tsc_rc"
fi

echo "::group::vite build"
bun x vite build 2>&1 | tee /tmp/vite.log
vite_rc=${PIPESTATUS[0]}
echo "::endgroup::"
if [ "$vite_rc" != 0 ]; then
  {
    echo "### vite build (exit $vite_rc)"
    echo '```'
    cat /tmp/vite.log
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
  tail -30 /tmp/vite.log | awk 'BEGIN{ORS="%0A"}{print}' | sed 's/^/::error::vite: /'
fi
exit "$vite_rc"
```


### Archived step: Build the docs site (FR-60) (original line 2096)

```text
cd ui
echo "::group::docs build"
bun docs/build.ts 2>&1 | tee /tmp/docs.log
docs_rc=${PIPESTATUS[0]}
echo "::endgroup::"
if [ "$docs_rc" != 0 ]; then
  {
    echo "### docs build (exit $docs_rc)"
    echo '```'
    cat /tmp/docs.log
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
  tail -30 /tmp/docs.log | awk 'BEGIN{ORS="%0A"}{print}' | sed 's/^/::error::docs: /'
fi
# The SEO files land at the site root, next to the SPA — assert
# they exist rather than trusting the generator's own log line.
test -f dist/sitemap.xml || { echo "::error::docs: dist/sitemap.xml missing"; exit 1; }
test -f dist/robots.txt || { echo "::error::docs: dist/robots.txt missing"; exit 1; }
test -f dist/docs/index.html || { echo "::error::docs: dist/docs/index.html missing"; exit 1; }
# FR-87: /sitemap.xml is an INDEX; the docs' URLs live in its child.
grep -q '<sitemapindex' dist/sitemap.xml || { echo "::error::docs: dist/sitemap.xml is not a sitemap index"; exit 1; }
test -f dist/sitemap-docs.xml || { echo "::error::docs: dist/sitemap-docs.xml missing"; exit 1; }
test -f dist/docs/404.html || { echo "::error::docs: dist/docs/404.html missing (nginx's error_page for /docs/ and /blog/)"; exit 1; }
# FR-87 P6: nginx answers `/` without a session cookie with this
# file, via `try_files $root_doc =404` — missing, every guest and
# every crawler would get a 404 at the site root.
test -f dist/home/index.html || { echo "::error::docs: dist/home/index.html missing (nginx serves it at / to guests and crawlers)"; exit 1; }
grep -q '<loc>https://meshharbor.itachi.fans/</loc>' dist/sitemap-docs.xml || { echo "::error::docs: / is missing from dist/sitemap-docs.xml"; exit 1; }
exit "$docs_rc"
```


### Archived step: Run unit tests (original line 2128)

```text
cd ui && bun run test:unit
```


### Archived step: Check every reduced profile compiles (original line 2177)

```text
for p in collab remote mesh access; do
  echo "::group::profile-$p"
  cargo check -p meshharbor-api --no-default-features --features "profile-$p"
  echo "::endgroup::"
done
```


### Archived step: Assert what each profile leaves out (AC3) (original line 2188)

```text
tree() { cargo tree -p meshharbor-api --no-default-features --features "profile-$1" -e normal --prefix none 2>/dev/null | awk '{print $1}' | sort -u; }
fail=0
for p in remote mesh access; do
  T=$(tree "$p"); N=$(printf '%s\n' "$T" | wc -l)
  if [ "$N" -lt 100 ]; then echo "::error::profile-$p: cargo tree returned $N crates — the assertion cannot be trusted"; fail=1; fi
  if printf '%s\n' "$T" | grep -qxE 'mediasoup(-sys)?'; then echo "::error::profile-$p links mediasoup"; fail=1; else echo "  profile-$p: no mediasoup ($N crates)"; fi
done
T=$(tree collab); N=$(printf '%s\n' "$T" | wc -l)
if [ "$N" -lt 100 ]; then echo "::error::profile-collab: cargo tree returned $N crates"; fail=1; fi
if printf '%s\n' "$T" | grep -qx 'meshharbor-tunnel-core'; then echo "::error::profile-collab links meshharbor-tunnel-core"; fail=1; else echo "  profile-collab: no tunnel-core ($N crates)"; fi
# And the positive control: the FULL graph must contain both, or
# the greps above prove nothing about the names they look for.
F=$(cargo tree -p meshharbor-api -e normal --prefix none 2>/dev/null | awk '{print $1}' | sort -u)
printf '%s\n' "$F" | grep -qx 'mediasoup' || { echo "::error::positive control failed: full does not list mediasoup"; fail=1; }
printf '%s\n' "$F" | grep -qx 'meshharbor-tunnel-core' || { echo "::error::positive control failed: full does not list meshharbor-tunnel-core"; fail=1; }
exit $fail
```


## hosted-image

Original path: `.github/workflows/hosted-image.yml`; SHA-256: `172a6e12005535e56dd80704a822360186d9641e3bdc528e83fa747bcddd706a`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Derive the tag (original line 83)

```text
set -euo pipefail
SHA="$(git rev-parse HEAD)"
SHA7="$(git rev-parse --short=7 HEAD)"
DATE="$(date -u +%Y%m%d)"
VERSION="$(git describe --tags --always)"
echo "tag=hosted-${DATE}-${SHA7}" >> "$GITHUB_OUTPUT"
echo "sha=$SHA" >> "$GITHUB_OUTPUT"
echo "version=$VERSION" >> "$GITHUB_OUTPUT"
echo "hosted-${DATE}-${SHA7}  version=$VERSION  sha=$SHA"
```


### Archived step: Docs dates manifest (original line 115)

```text
set -euo pipefail
cd ui
bun docs/dates.ts --write
```


### Archived step: GeoIP database (DB-IP, CC BY 4.0) (original line 132)

```text
bash scripts/fetch-geoip.sh files/geoip
```


### Archived step: Build clock — start (original line 136)

```text
echo "s=$(date +%s)" >> "$GITHUB_OUTPUT"
```


### Archived step: Build clock — stop (original line 159)

```text
S='${{ steps.t0.outputs.s }}'
E="$(date +%s)"
echo "secs=$((E - S))" >> "$GITHUB_OUTPUT"
echo "build took $((E - S)) s"
```


### Archived step: Labels name the commit (original line 169)

```text
set -euo pipefail
IMG='${{ env.IMAGE }}:${{ steps.tag.outputs.tag }}'
REV="$(docker image inspect "$IMG" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
VER="$(docker image inspect "$IMG" --format '{{ index .Config.Labels "org.opencontainers.image.version" }}')"
echo "  revision=$REV  version=$VER"
if [ "$REV" != '${{ steps.tag.outputs.sha }}' ]; then
  echo "::error::org.opencontainers.image.revision is '$REV', expected the built commit"
  exit 1
fi
```


### Archived step: Smoke — the image must actually serve, as the hosted composition (original line 184)

```text
set -euo pipefail
IMG='${{ env.IMAGE }}:${{ steps.tag.outputs.tag }}'
DBPW="$(openssl rand -hex 16)"
JWT="$(openssl rand -hex 32)"
docker network create meshharbor-smoke
docker run -d --name mongo --network meshharbor-smoke \
  -e MONGO_INITDB_ROOT_USERNAME=smoke -e MONGO_INITDB_ROOT_PASSWORD="$DBPW" mongo:7
docker run -d --name redis --network meshharbor-smoke redis:7-alpine
docker run -d --name meshharbor --network meshharbor-smoke -p 8080:80 \
  -e MESHHARBOR__APP__ENVIRONMENT=development \
  -e MESHHARBOR__JWT__SECRET="$JWT" \
  -e MESHHARBOR__DATABASE__URL="mongodb://smoke:${DBPW}@mongo:27017/?authSource=admin" \
  -e MESHHARBOR__REDIS__URL=redis://redis:6379 \
  -e MESHHARBOR__MEDIASOUP__NUM_WORKERS=1 \
  "$IMG"
for i in $(seq 1 60); do
  if curl -fsS -m 3 http://localhost:8080/health >/dev/null 2>&1; then
    echo "healthy after ${i}0s"
    curl -fsS http://localhost:8080/health; echo
    curl -fsS -o /dev/null -w '  GET / -> %{http_code}\n' http://localhost:8080/
    WANT='chat conference fleet network remote saas'
    GOT="$(curl -fsS http://localhost:8080/health | jq -r '.modules | sort | join(" ")')"
    if [ "$GOT" != "$WANT" ]; then
      echo "::error::the hosted image mounts [$GOT], expected [$WANT]"
      exit 1
    fi
    echo "  modules: $GOT ✓"
    DEV="$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/tenant/000000000000000000000000/device)"
    if [ "$DEV" != "401" ]; then
      echo "::error::GET /api/tenant/…/device answered $DEV, expected 401 — the device listing is not mounted"
      exit 1
    fi
    echo "  device listing: 401 ✓"
    # #1896: the image carries a country database and the server
    # LOADS it. A download that failed is a supported state (warn,
    # build on). A database the fetch step DID stage that the server
    # then does not load is our bug (the ENV and the file name
    # drifted, or the reader refused it), and it fails here rather
    # than as weeks of `unknown` on the dashboard.
    docker logs meshharbor > /tmp/meshharbor.log 2>&1 || true
    GEO="$(grep -m1 'geoip database' /tmp/meshharbor.log || true)"
    echo "  geoip: ${GEO:-no geoip line in the boot log}"
    if [ '${{ steps.geoip.outputs.present }}' = 'true' ]; then
      case "$GEO" in
        *'geoip database loaded'*'DBIP-Country-Lite'*)
          echo "  geoip: DB-IP database loaded ✓" ;;
        *)
          echo "::error::the fetch step staged a GeoIP database, but the server did not load it"
          exit 1 ;;
      esac
      # This smoke runs as root, which reads anything; a container
      # run as any other user must be able to read the file too.
      GEO_PATH="$(docker exec meshharbor printenv MESHHARBOR__STATS__GEOIP_MMDB)"
      if ! docker exec --user 65534:65534 meshharbor test -r "$GEO_PATH"; then
        echo "::error::$GEO_PATH is not readable by a non-root user: a container not run as root would read every country as 'unknown'"
        exit 1
      fi
      echo "  geoip: readable by a non-root user ✓"
    else
      echo "::warning title=No GeoIP database::this image carries none, so the user analytics will read every country as 'unknown'"
    fi
    # FR-87 (#1776) — how the public site is SERVED: relative redirects,
    # real 404s (no soft 404s), no-cache HTML, the Atom feed type, and every
    # static page keeping `/`'s security headers (one `add_header` in an
    # nginx location drops them all); content-hashed assets; and, given
    # this full-history checkout, every docs <lastmod> equal to git's.
    # The same script runs against production after a promote.
    bash scripts/public-site-smoke.sh http://localhost:8080 .
    exit 0
  fi
  sleep 10
done
echo "::error::the image did not answer /health within 600s"
docker logs meshharbor 2>&1 | tail -60
exit 1
```


### Archived step: Push the tag and move `hosted` (original line 264)

```text
set -euo pipefail
IMG='${{ env.IMAGE }}:${{ steps.tag.outputs.tag }}'
docker push "$IMG"
docker tag "$IMG" '${{ env.IMAGE }}:hosted'
docker push '${{ env.IMAGE }}:hosted'
D="$(docker buildx imagetools inspect "$IMG" --format '{{ .Manifest.Digest }}')"
echo "digest=$D" >> "$GITHUB_OUTPUT"
echo "pushed $IMG @ $D"
```


### Archived step: Summary (original line 288)

```text
if [ "$GEO_PRESENT" = true ]; then
  GEO="DB-IP IP to Country Lite $GEO_RELEASE (sha256 \`$GEO_SHA256\`)"
else
  GEO="none: every country reads \`unknown\`"
fi
{
  echo "## hosted image"
  echo
  echo "| | |"
  echo "|---|---|"
  echo "| tag | \`${{ steps.tag.outputs.tag }}\` |"
  echo "| commit | \`${{ steps.tag.outputs.sha }}\` (\`${{ steps.tag.outputs.version }}\`) |"
  echo "| build | ${{ steps.t1.outputs.secs }} s (cache: \`buildcache-hosted\`) |"
  echo "| geoip | $GEO |"
  echo "| pushed | ${{ steps.push.outputs.digest != '' && steps.push.outputs.digest || 'no' }} |"
  echo
  echo "Promote with the \`promote\` workflow (FR-73 P3) — this lane never deploys."
} >> "$GITHUB_STEP_SUMMARY"
```


## publish-selfhost-image

Original path: `.github/workflows/publish-selfhost-image.yml`; SHA-256: `4006abd0684211cad8f4c47dfb01239b71382a8bb0bf944b2fb5bdf52eba11b0`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Skip arm64 when not requested (original line 89)

```text
if [ '${{ matrix.arch }}' = 'arm64' ] && [ '${{ inputs.arm64 }}' != 'true' ]; then
  echo "skip=true" >> "$GITHUB_OUTPUT"
  echo "arm64 not requested — skipping"
else
  echo "skip=false" >> "$GITHUB_OUTPUT"
fi
```


### Archived step: Reject a tag that is not a tag (original line 102)

```text
TAG='${{ inputs.tag }}'
# A tag with a slash or a space produces a reference nobody can pull
# and, worse, one that looks fine in the run log.
if ! printf '%s' "$TAG" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$'; then
  echo "::error::tag '$TAG' is not a valid OCI tag (alnum start, then [A-Za-z0-9._-], <=127 chars)"
  exit 1
fi
echo "tag=$TAG" >> "$GITHUB_ENV"
```


### Archived step: Resolve the image tag for this profile (original line 119)

```text
PROFILE='${{ inputs.profile }}'
if [ "$PROFILE" = 'full' ]; then
  ITAG='${{ env.tag }}'
else
  ITAG='${{ env.tag }}'"-$PROFILE"
  if [ '${{ inputs.also_latest }}' = 'true' ]; then
    echo "::error::also_latest is only valid for profile=full — latest must stay the full image"
    exit 1
  fi
fi
echo "itag=$ITAG" >> "$GITHUB_ENV"
echo "  profile=$PROFILE  image tag=$ITAG"
```


### Archived step: GeoIP database (DB-IP, CC BY 4.0) (original line 156)

```text
bash scripts/fetch-geoip.sh files/geoip
```


### Archived step: Smoke test — the image must actually serve (original line 196)

```text
set -euo pipefail
IMG='${{ env.IMAGE }}:${{ env.itag }}-${{ matrix.arch }}'
# Generated per run, never written down. A literal here would be a
# credential-shaped string in a public repo — inert, but secret
# scanners cannot know that and neither can a reader skimming the
# file. These live for one job and die with the runner.
DBPW="$(openssl rand -hex 16)"
JWT="$(openssl rand -hex 32)"
docker network create meshharbor-smoke
docker run -d --name mongo --network meshharbor-smoke \
  -e MONGO_INITDB_ROOT_USERNAME=smoke -e MONGO_INITDB_ROOT_PASSWORD="$DBPW" mongo:7
docker run -d --name redis --network meshharbor-smoke redis:7-alpine
docker run -d --name meshharbor --network meshharbor-smoke -p 8080:80 \
  -e MESHHARBOR__APP__ENVIRONMENT=development \
  -e MESHHARBOR__JWT__SECRET="$JWT" \
  -e MESHHARBOR__DATABASE__URL="mongodb://smoke:${DBPW}@mongo:27017/?authSource=admin" \
  -e MESHHARBOR__REDIS__URL=redis://redis:6379 \
  -e MESHHARBOR__MEDIASOUP__NUM_WORKERS=1 \
  "$IMG"
for i in $(seq 1 60); do
  if curl -fsS -m 3 http://localhost:8080/health >/dev/null 2>&1; then
    echo "healthy after ${i}0s on ${{ matrix.arch }}"
    curl -fsS http://localhost:8080/health; echo
    # The SPA must be served too — an API-only container would pass a
    # /health check and still be useless as "the whole product".
    curl -fsS -o /dev/null -w '  GET / -> %{http_code}\n' http://localhost:8080/
    # FR-69 P8 — the image must BE the profile it claims. `/health`
    # lists the modules this binary mounts (not the DAG), so an image
    # built with the wrong features, or one that quietly kept `saas`,
    # fails here rather than on a self-hoster's box.
    WANT_full='chat conference fleet network remote'
    WANT_collab='chat conference'
    WANT_remote='fleet remote'
    WANT_mesh='fleet network'
    WANT_access='fleet network remote'
    eval "WANT=\$WANT_${{ inputs.profile }}"
    GOT=$(curl -fsS http://localhost:8080/health | jq -r '.modules | sort | join(" ")')
    if [ "$GOT" != "$WANT" ]; then
      echo "::error::profile '${{ inputs.profile }}' mounts [$GOT], expected [$WANT] — the image is not the profile it claims"
      exit 1
    fi
    case " $GOT " in *" saas "*) echo "::error::a self-host image must never carry saas"; exit 1;; esac
    echo "  modules: $GOT (profile ${{ inputs.profile }}) ✓"
    # The devices page's listing is the host's composition view over
    # fleet (required) and network (optional): every profile that
    # carries fleet must MOUNT it — 401 unauthenticated proves the
    # route exists, 404 proves it does not (the `remote` profile
    # shipped that 404 once, unnoticed by a smoke that read only
    # /health). collab has no fleet and must answer 404.
    DEV=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/tenant/000000000000000000000000/device)
    case " $GOT " in
      *" fleet "*) WANT_DEV=401 ;;
      *)           WANT_DEV=404 ;;
    esac
    if [ "$DEV" != "$WANT_DEV" ]; then
      echo "::error::GET /api/tenant/…/device answered $DEV, expected $WANT_DEV for profile ${{ inputs.profile }} — the device listing is not mounted where fleet is"
      exit 1
    fi
    echo "  device listing: $DEV ✓"
    # #1896: a staged country database must be one the server LOADS
    # (the same rule as the hosted lane). No database is a warning,
    # never a failure: a download outage must not block a release.
    docker logs meshharbor > /tmp/meshharbor.log 2>&1 || true
    GEO="$(grep -m1 'geoip database' /tmp/meshharbor.log || true)"
    echo "  geoip: ${GEO:-no geoip line in the boot log}"
    if [ '${{ steps.geoip.outputs.present }}' = 'true' ]; then
      case "$GEO" in
        *'geoip database loaded'*'DBIP-Country-Lite'*)
          echo "  geoip: DB-IP database loaded on ${{ matrix.arch }} ✓" ;;
        *)
          echo "::error::the fetch step staged a GeoIP database, but the ${{ matrix.arch }} server did not load it"
          exit 1 ;;
      esac
      # This smoke runs as root; a self-hoster may not (`user:` in
      # compose, runAsNonRoot), so the file must be world-readable.
      GEO_PATH="$(docker exec meshharbor printenv MESHHARBOR__STATS__GEOIP_MMDB)"
      if ! docker exec --user 65534:65534 meshharbor test -r "$GEO_PATH"; then
        echo "::error::$GEO_PATH is not readable by a non-root user: a container not run as root would read every country as 'unknown'"
        exit 1
      fi
      echo "  geoip: readable by a non-root user ✓"
    else
      echo "::warning title=No GeoIP database::this image carries none, so the user analytics will read every country as 'unknown'"
    fi
    exit 0
  fi
  sleep 10
done
echo "::error::${{ matrix.arch }} image did not answer /health within 600s"
docker logs meshharbor 2>&1 | tail -60
exit 1
```


### Archived step: Report the version the image reports about ITSELF (original line 291)

```text
set -uo pipefail
IMG='${{ env.IMAGE }}:${{ env.itag }}-${{ matrix.arch }}'
docker image inspect "$IMG" \
  --format '  labels: version={{index .Config.Labels "org.opencontainers.image.version"}} revision={{index .Config.Labels "org.opencontainers.image.revision"}}'
docker image inspect "$IMG" --format '  arch: {{.Architecture}}  size: {{.Size}} bytes'

# ⚠️ The tag and the binary's own version are DIFFERENT CLAIMS, and
# they drift silently: master moves while a 20-minute build runs, so
# a tag chosen when the dispatch was typed can already name a version
# this image is not. The first dry run produced exactly that —
# `version=v0.4.44` on a binary reporting `0.4.42`.
#
# A warning rather than a failure: `v1.0.0-rc1` and other deliberate
# names are legitimate, and refusing them would make the workflow
# unusable for the one case where a human has thought hardest about
# the tag. Being unmissable is what this needs to be.
WS=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
TAG='${{ env.tag }}'
echo "  workspace version: $WS"
if [ "${TAG#v}" != "$WS" ]; then
  echo "::warning title=Tag does not match the workspace version::\
tag '$TAG' vs Cargo.toml '$WS'. The image will report $WS about itself \
while the registry calls it $TAG. Intended for a release candidate; \
a mistake if you meant v$WS."
else
  echo "  ✓ tag matches the version the binary reports"
fi
```


### Archived step: Push by digest (original line 333)

```text
set -euo pipefail
SRC='${{ env.IMAGE }}:${{ env.itag }}-${{ matrix.arch }}'
docker push "$SRC"
DIGEST=$(docker image inspect "$SRC" --format '{{index .RepoDigests 0}}' | cut -d@ -f2)
echo "  ${{ matrix.arch }} -> $DIGEST"
mkdir -p /tmp/digests
echo "$DIGEST" > "/tmp/digests/${{ matrix.arch }}"
```


### Archived step: Assemble the manifest (original line 382)

```text
set -euo pipefail
# FR-69 P8 — the same tag rule the build job applied (the merge job
# has no env from it): `<tag>` for full, `<tag>-<profile>` otherwise.
TAG='${{ inputs.tag }}'
if [ '${{ inputs.profile }}' != 'full' ]; then
  TAG="$TAG-${{ inputs.profile }}"
fi
REFS=""
FOUND=""
for a in amd64 arm64; do
  if [ -f "/tmp/digests/$a" ]; then
    D=$(cat "/tmp/digests/$a")
    REFS="$REFS ${{ env.IMAGE }}@$D"
    FOUND="$FOUND $a"
  fi
done
if [ -z "$REFS" ]; then
  echo "::error::no architecture produced a digest — nothing to publish"
  exit 1
fi
# Say what is NOT in the tag. A manifest quietly missing an arch is
# indistinguishable from one that never wanted it, and the person who
# finds out is a Pi owner whose pull fails.
case "$FOUND" in
  *amd64*arm64*) echo "  both architectures present" ;;
  *) echo "::warning title=Publishing a single-architecture image::\
only[$FOUND ] succeeded. The tag will publish, but hosts on the missing \
architecture cannot pull it." ;;
esac
# shellcheck disable=SC2086
docker buildx imagetools create --tag "${{ env.IMAGE }}:$TAG" $REFS
if [ '${{ inputs.also_latest }}' = 'true' ]; then
  # shellcheck disable=SC2086
  docker buildx imagetools create --tag "${{ env.IMAGE }}:latest" $REFS
  echo "  moved latest"
fi
LIST=$(docker buildx imagetools inspect "${{ env.IMAGE }}:$TAG" \
  --format '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}} {{end}}' 2>/dev/null || true)
echo "  published platforms: $LIST"
D=$(docker buildx imagetools inspect "${{ env.IMAGE }}:$TAG" --format '{{.Manifest.Digest}}')
echo "digest=$D" >> "$GITHUB_OUTPUT"
echo "platforms=$LIST" >> "$GITHUB_OUTPUT"
echo "itag=$TAG" >> "$GITHUB_OUTPUT"
```


### Archived step: Summary (original line 439)

```text
{
  echo "### Self-host image"
  echo
  echo '```'
  echo 'docker pull ${{ env.IMAGE }}:${{ steps.manifest.outputs.itag }}'
  echo '```'
  echo
  echo "Profile: \`${{ inputs.profile }}\`"
  echo
  echo "Platforms: \`${{ steps.manifest.outputs.platforms }}\`"
  echo
  echo "\`latest\` moved: \`${{ inputs.also_latest }}\`"
  echo
  echo "Digest: \`${{ steps.manifest.outputs.digest }}\`"
} >> "$GITHUB_STEP_SUMMARY"
```


## hive-archive-image

Original path: `.github/workflows/hive-archive-image.yml`; SHA-256: `89fd50027bc6c0f258c5cb7e2b4058bcc52bf479287281a22cb3e6492a4c90cb`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve the tag (original line 61)

```text
if [ '${{ github.event_name }}' = 'workflow_dispatch' ]; then
  TAG='${{ inputs.tag }}'
  # A tag with a slash or a space makes a reference nobody can pull.
  if ! printf '%s' "$TAG" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$'; then
    echo "::error::tag '$TAG' is not a valid OCI tag (alnum start, then [A-Za-z0-9._-], <=127 chars)"
    exit 1
  fi
else
  TAG="pr-${{ github.event.pull_request.number }}"
fi
echo "tag=$TAG" >> "$GITHUB_ENV"
```


### Archived step: Smoke test (original line 95)

```text
set -euo pipefail
IMG='${{ env.IMAGE }}:${{ env.tag }}'
# The binary starts, with the libraries it links.
docker run --rm --entrypoint meshharbord "$IMG" --version
# It is the build that enrolls archive replicas.
docker run --rm --entrypoint meshharbord "$IMG" enroll --help | grep -q -- '--archive-replica'
# It runs as no one in particular, with the volume as its home.
test "$(docker run --rm --entrypoint id "$IMG" -u)" = 10001
# It says it is the archive image, so an archive replica enrolled
# before the posture joined the mesh joins it here (FR-90 P2k-4).
test "$(docker run --rm --entrypoint printenv "$IMG" MESHHARBORD_ARCHIVE_IMAGE)" = 1
# A first start with nothing to enroll with says why, and fails.
set +e
out=$(docker run --rm "$IMG" 2>&1); rc=$?
set -e
echo "$out"
test "$rc" -ne 0
echo "$out" | grep -q 'MESHHARBOR_SERVER'
# An enrollment that fails writes nothing: the volume stays empty,
# and the next start enrolls again. (Port 9 refuses at once: no
# network is needed, and no server is told anything.)
docker volume create hive-archive-smoke >/dev/null
set +e
out=$(docker run --rm -v hive-archive-smoke:/data \
  -e MESHHARBOR_SERVER=http://127.0.0.1:9 -e MESHHARBOR_ENROLL_TOKEN=not-a-token \
  "$IMG" 2>&1); rc=$?
set -e
echo "$out" | grep -v 'not-a-token' || true
test "$rc" -ne 0
if echo "$out" | grep -q 'not-a-token'; then
  echo "::error::the entrypoint printed the enrollment token"
  exit 1
fi
docker run --rm -v hive-archive-smoke:/data --entrypoint sh "$IMG" \
  -c 'test ! -e /data/config.toml'
docker volume rm hive-archive-smoke >/dev/null
echo "smoke ok"
```


### Archived step: Publish (original line 144)

```text
set -euo pipefail
docker push '${{ env.IMAGE }}:${{ env.tag }}'
if [ '${{ inputs.also_latest }}' = 'true' ]; then
  docker tag '${{ env.IMAGE }}:${{ env.tag }}' '${{ env.IMAGE }}:latest'
  docker push '${{ env.IMAGE }}:latest'
fi
```


## sign-windows

Original path: `.github/actions/sign-windows/action.yml`; SHA-256: `5a026425afc0362cd098d844266a3b1cfede7983c2d4dbda5c75e8a3eca4feb2`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve signing mode and file set (original line 197)

```text
$ErrorActionPreference = 'Stop'

# `require` defaults to "true on a tag": a release must never be able
# to publish unsigned, but a PR or a dispatch rehearsal should stay
# green so packaging can be iterated without credentials.
$require = switch ($env:IN_REQUIRE) {
  'true'  { $true }
  'false' { $false }
  default { $env:REF_TYPE -eq 'tag' }
}

$azureReady = [bool]($env:IN_ENDPOINT -and $env:IN_ACCOUNT -and $env:IN_PROFILE -and $env:IN_CLIENTID -and $env:IN_TENANT)
$localReady = [bool]$env:IN_PFX

$mode = switch ($env:IN_MODE) {
  'off'   { 'none' }
  'azure' {
    if (-not $azureReady) {
      Write-Host "::error::mode=azure but the Azure inputs are incomplete (endpoint/account/profile/client-id/tenant-id). Run scripts/signing/30-github-oidc.ps1."
      exit 1
    }
    'azure'
  }
  'local' {
    if (-not $localReady) {
      Write-Host "::error::mode=local but local-pfx-base64 is empty. Run scripts/signing/50-selfsigned-dev-cert.ps1 -PushSecrets."
      exit 1
    }
    'local'
  }
  default {
    if     ($azureReady) { 'azure' }
    elseif ($localReady) { 'local' }
    else                 { 'none' }
  }
}

# Expand the file set. Absolute paths win; relative resolve against
# the workspace, which is where every call site's paths are rooted.
$resolved = New-Object System.Collections.Generic.List[string]
$missing  = New-Object System.Collections.Generic.List[string]

function Add-Path([string]$p) {
  $p = $p.Trim().Trim('"')
  if (-not $p) { return }
  if (-not [IO.Path]::IsPathRooted($p)) { $p = Join-Path $env:GITHUB_WORKSPACE $p }
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $resolved.Add((Resolve-Path -LiteralPath $p).Path)
  } else {
    $missing.Add($p)
  }
}

foreach ($tok in ($env:IN_FILES -split "[`r`n,]")) { Add-Path $tok }

if ($env:IN_FOLDER) {
  $folder = $env:IN_FOLDER
  if (-not [IO.Path]::IsPathRooted($folder)) { $folder = Join-Path $env:GITHUB_WORKSPACE $folder }
  if (Test-Path -LiteralPath $folder) {
    $exts = @()
    foreach ($e in ($env:IN_FILTER -split ',')) {
      $e = $e.Trim().TrimStart('*').TrimStart('.')
      if ($e) { $exts += ('.' + $e.ToLower()) }
    }
    $gc = @{ LiteralPath = $folder; File = $true }
    if ($env:IN_RECURSE -eq 'true') { $gc['Recurse'] = $true }
    # Filter extensions in PowerShell rather than with -Include:
    # -Include is silently ignored alongside -LiteralPath -Recurse
    # (it matched every file at the top level, .txt included). A
    # signing file set is the last place to accept that surprise.
    foreach ($f in (Get-ChildItem @gc)) {
      if ($exts.Count -eq 0 -or $exts -contains $f.Extension.ToLower()) {
        $resolved.Add($f.FullName)
      }
    }
  } else {
    $missing.Add($folder)
  }
}

# A path that does not exist is always a bug at the call site -- a
# renamed artifact, a step that did not run, a typo. Never silently
# sign a smaller set than was asked for.
if ($missing.Count -gt 0) {
  foreach ($m in $missing) { Write-Host "::error::sign-windows: path not found: $m" }
  exit 1
}

$resolved = $resolved | Select-Object -Unique
if ($resolved.Count -eq 0) {
  Write-Host "::error::sign-windows: resolved an EMPTY file set. Check the 'files' / 'files-folder' inputs at the call site."
  exit 1
}

$listPath = Join-Path $env:RUNNER_TEMP 'sign-windows-files.txt'
$resolved | Set-Content -LiteralPath $listPath -Encoding utf8

Write-Host "mode=$mode  require=$require  files=$($resolved.Count)"
foreach ($r in $resolved) { Write-Host "  $r" }

"mode=$mode"                          | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"require=$($require.ToString().ToLower())" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"count=$($resolved.Count)"            | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"list_path=$listPath"                 | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"files_list<<__SIGN_EOF__"            | Out-File -FilePath $env:GITHUB_OUTPUT -Append
($resolved -join "`n")                | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"__SIGN_EOF__"                        | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Sign with the local test certificate (original line 354)

```text
$ErrorActionPreference = 'Stop'

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Write-Host "::error::signtool.exe not found on this runner."; exit 1 }

$pfxPath = Join-Path $env:RUNNER_TEMP 'sign-windows-local.pfx'
[IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:PFX_B64))

if ($env:TRUST_STORE -eq 'true') {
  # Only the PUBLIC certificate goes into Root/TrustedPublisher; the
  # private key stays in the PFX that signtool reads and that the
  # cleanup step deletes.
  $pfx = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @($pfxPath, $env:PFX_PW, 'Exportable')
  $pub = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$pfx.Export('Cert'))
  foreach ($storeName in @('Root', 'TrustedPublisher')) {
    $store = New-Object Security.Cryptography.X509Certificates.X509Store @($storeName, 'LocalMachine')
    $store.Open('ReadWrite')
    $store.Add($pub)
    $store.Close()
    Write-Host "imported $($pub.Subject) into LocalMachine\$storeName"
  }
}

$files = Get-Content -LiteralPath $env:LIST_PATH
$args = @('sign', '/f', $pfxPath, '/p', $env:PFX_PW, '/fd', $env:FILE_DIGEST)
if ($env:TSA) { $args += @('/tr', $env:TSA, '/td', $env:FILE_DIGEST) }
$args += $files

& $signtool.FullName @args
if ($LASTEXITCODE -ne 0) { Write-Host "::error::local signtool sign failed ($LASTEXITCODE)"; exit 1 }
```


### Archived step: Verify signatures (original line 401)

```text
$ErrorActionPreference = 'Stop'

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" |
            Sort-Object FullName -Descending | Select-Object -First 1

$files    = Get-Content -LiteralPath $env:LIST_PATH
$problems = New-Object System.Collections.Generic.List[string]
$subject  = ''

foreach ($f in $files) {
  $name = Split-Path -Leaf $f
  $sig  = Get-AuthenticodeSignature -LiteralPath $f

  if ($sig.Status -eq 'NotSigned') { $problems.Add("$name is NOT SIGNED"); continue }

  $certSubject = $sig.SignerCertificate.Subject
  $cn = if ($certSubject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $certSubject }
  if (-not $subject) { $subject = $certSubject }

  if ($env:VERIFY_MODE -eq 'strict') {
    # /pa = Authenticode policy (what Windows itself applies to an
    # EXE/MSI); /all = every signature, not just the first.
    & $signtool.FullName verify /pa /all /q $f 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
      $problems.Add("$name failed 'signtool verify /pa /all' (status=$($sig.Status))")
      continue
    }
  } elseif ($sig.Status -ne 'Valid' -and $sig.Status -ne 'UnknownError') {
    $problems.Add("$name signature status = $($sig.Status)")
    continue
  }

  if ($env:REQUIRE_TS -eq 'true' -and -not $sig.TimeStamperCertificate) {
    $problems.Add("$name has NO RFC3161 timestamp -- the signature expires with the certificate")
    continue
  }

  if ($env:EXPECT_SUBJECT -and $cn -notlike "*$($env:EXPECT_SUBJECT)*") {
    $problems.Add("$name signer CN '$cn' does not contain '$($env:EXPECT_SUBJECT)'")
    continue
  }

  $ts = if ($sig.TimeStamperCertificate) { 'timestamped' } else { 'no timestamp' }
  Write-Host "  OK  $name  [$cn, $ts]"
}

if ($problems.Count -gt 0) {
  foreach ($p in $problems) { Write-Host "::error::sign-windows verify: $p" }
  "verified=false" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
  "subject="       | Out-File -FilePath $env:GITHUB_OUTPUT -Append
  exit 1
}

"verified=true"      | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"subject=$subject"   | Out-File -FilePath $env:GITHUB_OUTPUT -Append
```


### Archived step: Remove local key material (original line 464)

```text
$pfx = Join-Path $env:RUNNER_TEMP 'sign-windows-local.pfx'
if (Test-Path $pfx) {
  Remove-Item $pfx -Force -ErrorAction SilentlyContinue
  Write-Host 'removed the staged test PFX'
}
```


### Archived step: Report (original line 485)

```text
$ErrorActionPreference = 'Stop'

$signed = ($env:MODE -ne 'none') -and ($env:VERIFIED -eq 'true' -or $env:VERIFY_MODE -eq 'off')
$cn = if ($env:SUBJECT -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $env:SUBJECT }

"signed=$($signed.ToString().ToLower())" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
"subject=$($env:SUBJECT)"                | Out-File -FilePath $env:GITHUB_OUTPUT -Append

$line = if ($signed) {
  "signed + verified -- $($env:COUNT) file(s), mode=$($env:MODE), publisher=$cn"
} else {
  "**UNSIGNED** -- $($env:COUNT) file(s), mode=$($env:MODE)"
}
"* sign-windows: $line" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
Write-Host $line

if (-not $signed) {
  if ($env:REQUIRE -eq 'true') {
    Write-Host "::error::Windows artifacts are UNSIGNED and signing is REQUIRED for this run (release tag, or require_signing=true). Configure Azure Artifact Signing (scripts/signing/) or dispatch with signing_mode=local."
    exit 1
  }
  Write-Host "::warning::Windows artifacts are UNSIGNED (mode=$($env:MODE)). SmartScreen will show 'Unknown publisher' and corporate AV may quarantine them."
}
```


## sign-macos

Original path: `.github/actions/sign-macos/action.yml`; SHA-256: `3002aba4bff9e2c22e8d27de4c283f6ede7047e7ffb62b294429f981cba78f31`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Resolve Apple signing mode (original line 90)

```text
set -euo pipefail

case "${IN_REQUIRE:-}" in
  true)  require=true ;;
  false) require=false ;;
  *)     if [[ "$REF_TYPE" == "tag" ]]; then require=true; else require=false; fi ;;
esac

# Notarisation needs the API key; signing needs the p12s. Demand all
# six together so a half-configured run can never produce a
# signed-but-unnotarised artifact, which Gatekeeper rejects just as
# hard as an unsigned one but looks fine in the logs.
req=(APP_P12 INSTALLER_P12 CERT_PW KEY_ID ISSUER_ID KEY_P8)
have=(); miss=()
for v in "${req[@]}"; do
  if [[ -n "${!v:-}" ]]; then have+=("$v"); else miss+=("$v"); fi
done

if [[ ${#miss[@]} -eq 0 ]]; then
  mode=full
elif [[ ${#have[@]} -eq 0 ]]; then
  mode=none
else
  echo "::error::sign-macos: Apple credentials are PARTIALLY configured (missing: ${miss[*]}). Signing is all-or-nothing. Run scripts/signing/60-apple-setup.sh check."
  exit 1
fi

if [[ -z "$BUNDLE" && -z "$BINARY" ]]; then
  echo "::error::sign-macos: pass either bundle-path or binary-path."
  exit 1
fi
if [[ -n "$BUNDLE" && -n "$BINARY" ]]; then
  echo "::error::sign-macos: pass exactly ONE of bundle-path / binary-path."
  exit 1
fi

target="${BUNDLE:-$BINARY}"
if [[ ! -e "$target" ]]; then
  echo "::error::sign-macos: target not found: $target"
  exit 1
fi

if [[ "$mode" == none && "$require" == true ]]; then
  echo "::error::sign-macos: no Apple credentials and signing is REQUIRED for this run. An unsigned macOS artifact is blocked by Gatekeeper on end-user Macs."
  exit 1
fi

echo "mode=$mode"           >> "$GITHUB_OUTPUT"
echo "require=$require"     >> "$GITHUB_OUTPUT"
echo "target=$target"       >> "$GITHUB_OUTPUT"
echo "is_bundle=$([[ -n "$BUNDLE" ]] && echo true || echo false)" >> "$GITHUB_OUTPUT"
echo "sign-macos: mode=$mode require=$require target=$target"
```


### Archived step: Import signing certs (original line 151)

```text
set -euo pipefail
KEYCHAIN=meshharbor-signing.keychain
KEYCHAIN_PASSWORD=$(openssl rand -hex 24)

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

echo "$APP_P12" | base64 -d > /tmp/rl-app.p12
security import /tmp/rl-app.p12 -k "$KEYCHAIN" -P "$CERT_PW" \
  -T /usr/bin/codesign -T /usr/bin/security

echo "$INSTALLER_P12" | base64 -d > /tmp/rl-installer.p12
security import /tmp/rl-installer.p12 -k "$KEYCHAIN" -P "$CERT_PW" \
  -T /usr/bin/productbuild -T /usr/bin/security

security list-keychain -d user -s "$KEYCHAIN" login.keychain
security set-key-partition-list -S apple-tool:,apple: \
  -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

rm -f /tmp/rl-app.p12 /tmp/rl-installer.p12
security find-identity -v -p codesigning "$KEYCHAIN"
```


### Archived step: Codesign (original line 182)

```text
set -euo pipefail
args=(--sign "Developer ID Application" --options runtime --timestamp --force)
if [[ -n "$ENTITLEMENTS" ]]; then args+=(--entitlements "$ENTITLEMENTS"); fi

if [[ "$IS_BUNDLE" == true ]]; then
  # Inside-out: nested code must be signed before the bundle that
  # contains it, or notarisation rejects the lot.
  if [[ -d "$TARGET/Contents/Frameworks" ]]; then
    find "$TARGET/Contents/Frameworks" -type f \( -name '*.dylib' -o -name '*.so' \) -print0 \
      | while IFS= read -r -d '' lib; do
          codesign --sign "Developer ID Application" --options runtime --timestamp --force "$lib"
        done
  fi
  exe="$TARGET/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$TARGET/Contents/Info.plist")"
  codesign "${args[@]}" "$exe"
  codesign --sign "Developer ID Application" --options runtime --timestamp --force "$TARGET"
else
  codesign "${args[@]}" "$TARGET"
fi

codesign --verify --strict --verbose=2 "$TARGET"
```


### Archived step: Notarise (original line 214)

```text
set -euo pipefail
mkdir -p ~/.appstoreconnect/private_keys
keyfile="$HOME/.appstoreconnect/private_keys/AuthKey_${KEY_ID}.p8"
echo "$KEY_P8" | base64 -d > "$keyfile"

# notarytool takes an archive, never a loose binary or bundle.
# `ditto -c -k --keepParent` is the only zip form Apple accepts for a
# bundle (it preserves the resource forks / extended attributes that
# /usr/bin/zip drops).
zipfile="$RUNNER_TEMP/notarize.zip"
ditto -c -k --keepParent "$TARGET" "$zipfile"

xcrun notarytool submit "$zipfile" \
  --key "$keyfile" --key-id "$KEY_ID" --issuer "$ISSUER_ID" --wait

if [[ "$IS_BUNDLE" == true ]]; then
  # Staple only works on a bundle/.dmg/.pkg. The ticket lands as a
  # regular file INSIDE the bundle, so it survives tar/untar and the
  # artifact validates on an offline Mac.
  # Retried: since 2026-10-12 the ticket fetch drops its connection on
  # GitHub's macOS runners after `Accepted` (exit 68; the script says why).
  bash "$GITHUB_ACTION_PATH/../../../scripts/signing/stapler-retry.sh" staple "$TARGET"
  bash "$GITHUB_ACTION_PATH/../../../scripts/signing/stapler-retry.sh" validate "$TARGET"
else
  echo "::notice::$TARGET is a bare Mach-O -- notarised but NOT stapled (Apple does not support stapling a loose executable). Gatekeeper will perform an ONLINE notarisation lookup; an offline Mac will refuse a browser-downloaded copy. Install paths that use curl|tar do not set the quarantine attribute, so they are unaffected."
fi

rm -f "$keyfile" "$zipfile"
```


### Archived step: Verify (original line 251)

```text
set -euo pipefail
codesign --verify --strict --verbose=2 "$TARGET"

# Hardened runtime is mandatory for notarisation; assert it rather
# than trusting that --options runtime took effect.
codesign -d --verbose=2 "$TARGET" 2>&1 | grep -q 'flags=.*runtime' \
  || { echo "::error::hardened runtime NOT enabled on $TARGET"; exit 1; }

if [[ "$NOTARIZE" == "true" && "$IS_BUNDLE" == true ]]; then
  bash "$GITHUB_ACTION_PATH/../../../scripts/signing/stapler-retry.sh" validate "$TARGET"
  out="$(spctl -a -vvv "$TARGET" 2>&1 || true)"
  echo "$out"
  echo "$out" | grep -q 'source=Notarized Developer ID' \
    || { echo "::error::spctl did not report 'source=Notarized Developer ID' for $TARGET"; exit 1; }
fi
echo "sign-macos: verified $TARGET"
```


### Archived step: Remove the ephemeral keychain (original line 272)

```text
security delete-keychain meshharbor-signing.keychain 2>/dev/null || true
```


### Archived step: Report (original line 282)

```text
set -euo pipefail
if [[ "$MODE" == "full" ]]; then
  echo "signed=true" >> "$GITHUB_OUTPUT"
  echo "* sign-macos: signed + notarised -- $TARGET" >> "$GITHUB_STEP_SUMMARY"
else
  echo "signed=false" >> "$GITHUB_OUTPUT"
  echo "* sign-macos: **UNSIGNED** -- $TARGET" >> "$GITHUB_STEP_SUMMARY"
  if [[ "$REQUIRE" == "true" ]]; then
    echo "::error::macOS artifact is unsigned and signing is REQUIRED for this run."
    exit 1
  fi
  echo "::warning::macOS artifact is unsigned -- Gatekeeper will block it on end-user Macs."
fi
```


## ci-linux-system-deps

Original path: `.github/actions/ci-linux-system-deps/action.yml`; SHA-256: `7e0fbba7cba4e40497ca0287f11f1e495a3bd2d5299d5766d2c95181794164dd`.

> **Retired reference section.** All blocks below preserve original runner commands,
> including any signing/publication/setup side effects. They are not an executable
> local workflow. Use the current [local build policy](local-build.md) instead.


### Archived step: Configure apt retries and refresh the index (original line 44)

```text
echo 'Acquire::Retries "3";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries
sudo apt-get update -qq
```


### Archived step: Verify the GTK set really landed (fallback to apt-get) (original line 96)

```text
if ! pkg-config --exists glib-2.0 webkit2gtk-4.1; then
  echo "::warning::cached apt set did not deliver the GTK dev packages — installing directly"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    libglib2.0-dev libgtk-3-dev libsoup-3.0-dev \
    libjavascriptcoregtk-4.1-dev libwebkit2gtk-4.1-dev pkg-config
fi
for m in glib-2.0 gtk+-3.0 webkit2gtk-4.1; do
  pkg-config --exists "$m" || { echo "::error::$m still not found by pkg-config after the fallback install"; exit 1; }
done
```


### Archived step: Verify libvpx really landed (fallback to apt-get) (original line 150)

```text
sudo ldconfig
if ! ldconfig -p | grep -q 'libvpx\.so'; then
  echo "::warning::cached apt set did not deliver libvpx — installing directly"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends libvpx-dev pkg-config libxcb1-dev libxcb-shm0-dev libxcb-randr0-dev cmake libclang-dev libasound2-dev
fi
ldconfig -p | grep 'libvpx\.so' || { echo "::error::libvpx.so still not loadable after the fallback install"; exit 1; }
```
