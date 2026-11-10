# Local builds, packages and corresponding source

## Project policy

MeshHarbor permanently uses **no CI**. Pushes, pull requests, tags and schedules
must not trigger builds, tests, signing, publishing or deployment. Do not restore
GitHub workflows or composite actions as a shortcut. This is a project rule,
requested by the owner on 2026-11-05; it does not disable local verification.
Oracle: `.github/workflows/` and `.github/actions/` contain no tracked files.
Historical FR records describe retired automation, not current instructions.

Run only the checks relevant to the change, on an isolated authorized host.
Keep outputs/caches outside synchronized source. Compilation is not signing;
signing is not publication; a successful build is not a deployment or field test.
For the current local artifacts, the owner chose **unsigned Windows and Linux
builds; only macOS is signed**. Do not invoke Windows signing or Linux/GPG
signing as a prerequisite for these local builds.
No download, signing, installation or release was performed by this migration.
The commands below are local entrypoints, not a claim of cross-platform validation.

## Toolchain and checks

`rust-toolchain.toml` pins Rust **1.95.0**, rustfmt and clippy. Keep `Cargo.lock`
and vendored dependency patches; do not uninstall user toolchains to mimic a runner.
Linux native prerequisites include pkg-config, cmake, nasm, clang/libclang, libdbus-1-dev,
libglib2.0-dev, libgtk-3-dev, libsoup-3.0-dev, libjavascriptcoregtk-4.1-dev,
libwebkit2gtk-4.1-dev, libvpx-dev, libxcb1-dev, libxcb-shm0-dev,
libxcb-randr0-dev and libasound2-dev, according to selected features.
The former dependency checks can be inspected through the
[historical sources](#historical-workflow-sources), including the retired
`ci-linux-system-deps` action. They are not a local setup script.
Windows needs MSVC, Windows SDK, pkg-config, nasm and native dependencies; macOS needs
Xcode tools and the target-specific dependencies. Package/signing tools are separate.
Release builds of `meshharbord` with `openh264-encoder` on `x86`/`x86_64` require
`nasm` in `PATH` so `openh264-src` compiles x86 SIMD assembly (`build.rs` fails
closed in `release` profile when `nasm` is missing unless
`MESHHARBORD_ALLOW_OPENH264_NO_NASM=1` is explicitly set; non-release profiles
emit a `cargo:warning`).

```sh
cargo fmt --all -- --check
# Manual Linux checks; --quick skips the overlay/agent feature combinations.
bash scripts/ci-local.sh --quick
# These can compile substantial native dependencies; choose relevant targets.
cargo clippy -p meshharbor-api -p meshharbor-services --all-targets -- -D warnings
cargo check -p meshharbor-tests --all-targets
cargo test -p meshharbor-tunnel-core --features overlay-l3,overlay-netstack --lib -- --test-threads=1
bash scripts/fr-registry-audit.sh
bash scripts/anchor-range-audit.sh
bash scripts/apply-spdx.sh --check
cargo deny check licenses
```

Run `cargo tree -p <shipped-agent> -e normal` and check against the server crate
list in `scripts/licence-classes.sh`; dev dependencies are not shipped edges.
The former manifest-license/graph algorithms and platform feature matrices are
in the historical `licensing.yml` and `ci.yml` sources; see
[historical workflow sources](#historical-workflow-sources). Workspace checks alone do not cover feature unions,
platform-specific code or `#[cfg(test)]` bodies. For a reduced API profile, use
`--no-default-features --features <profile>` and assert both expected presences
and absences with `cargo tree`, plus a full-profile positive control.

```sh
# UI commands are run from ui/ (Bun version/dependencies follow its lockfiles).
bun run test:unit
bun run build
# Isolated Mongo/Redis are prerequisites; never target unrelated services.
RUST_MIN_STACK=8388608 cargo test -p meshharbor-tests <exact-filter> -- --exact --nocapture
```

The last command is run from repository root. Require a nonzero expected test
count and terminal success; zero matched tests is not a passing oracle. Keep
logs and verify owned database/process/port cleanup. GUI, capture, fleet, route
and privileged installer tests need their own authorized isolation. Local checks
do not prove the real-network acceptance bar in CLAUDE.md.

## Native binaries and features

Run each line on the matching native host/target with its libraries already
staged. These are the R3 release feature sets, not a promise every target was
built here. Historical prerequisite, linker, companion, shim, packaging and
verification details remain in Git as `release-agent.yml`; use the
[historical source index](#historical-workflow-sources). Those retired runner
commands are not an executable local build plan.

| Platform | Agent command |
|---|---|
| Linux x86_64 | `cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ffmpeg-encoder,ssh-server,viewer-indicator-x11"` |
| Linux arm64 | `cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ssh-server,viewer-indicator-x11"` |
| Windows x64 | `cargo build -p meshharbord --release --features "full-hw,hive,vp9-444,system-context,ffmpeg-encoder,overlay-l3,overlay-netstack,ssh-server"` |
| macOS arm64 | `cargo build -p meshharbord --release --features "full,hive,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ssh-server,ffmpeg-encoder" --target aarch64-apple-darwin` |

Windows also requires the original `CMAKE_POLICY_VERSION_MINIMUM=3.5` compatibility
setting where used. `vp9-444-bindgen` is intentionally absent on Windows, which
uses bindings matching libvpx 1.12.0. **Do not set `FFMPEG_DIR` on Windows**, and
clear it if inherited in the build shell. Configure the FFmpeg and libvpx `.pc`
directories through `PKG_CONFIG_PATH`, as in `scripts/dev-ffmpeg-windows.ps1:164`.
Setting `FFMPEG_DIR` bypasses pkg-config in ffmpeg-sys-next and omits transitive
libraries such as libvpl (`MFX*` symbols), advapi32 and ole32. Keep
`PKG_CONFIG_ALLOW_SYSTEM_LIBS=1` as the existing helper specifies. The helper's
current default repository is historical; pass `-Repo gjovanov/roomler-ai` for
the verified upstream Windows assets rather than relying on that default.
Read the helper before invocation: staging can download/install dependencies.

Linux/macOS shared-library builds may use `FFMPEG_DIR` together with the matching
`PKG_CONFIG_PATH`; that convenience is not a Windows instruction. Check the
selected tree's `.pc` paths and `MESHHARBOR-PATCHES.txt` before linking. Linux
arm64's retained R3 release feature set intentionally lacks `ffmpeg-encoder`.

CLI: `cargo build -p meshharbor-cli --release`. Setup:
`cargo build -p meshharbor-setup --release`. Historical `release-setup.yml` and
`release-tunnel.yml` sources retain the target flags, strip/compression and
package asset names; retrieve them through the
[historical source index](#historical-workflow-sources). macOS universal
setup/CLI builds combine `x86_64-apple-darwin` and `aarch64-apple-darwin` using
`lipo`; the daemon release is Apple silicon only. Companion and shim commands
are distinct from the daemon; never let a companion `.deb` become the first
agent-update asset. Preserve `agent_release::order_assets_daemon_first`.

## Vendor inputs and assets

Source URLs below are the **retained R3 recipe inputs**, not downloads performed
by this migration or proof of the assets currently served under a release tag.
The task's Windows asset check located these two vendor releases at the public
upstream repository **`gjovanov/roomler-ai`**:

- `https://github.com/gjovanov/roomler-ai/releases/tag/vendored-ffmpeg-9.0.1`
- `https://github.com/gjovanov/roomler-ai/releases/tag/vendored-libvpx-1.12.0`

The upstream FFmpeg patch manifest and this checkout's patch inputs differ;
review the exact asset hashes, shipped manifest and actual build revision before
mapping that asset to a source offer. A shared tag/version is not provenance.
This migration has not established that mapping. Linux/macOS asset availability
and their actual release repositories have not been verified here. Their asset
names below are historical recipe names, not assertions that those URLs exist.
On Windows, reuse the existing staging helper with the explicit upstream `-Repo`
above; do not change a frozen source recipe or assume its default repository is
where the verified upstream binaries reside.

| Input | Exact pin / source |
|---|---|
| FFmpeg | `n9.0.1`, <https://github.com/FFmpeg/FFmpeg.git>, source archive `https://github.com/FFmpeg/FFmpeg/archive/refs/tags/n9.0.1.tar.gz` |
| Windows FFmpeg vcpkg | `2e6b92385d891ae14291b7b926863f74ed59a7ad`, <https://github.com/microsoft/vcpkg.git>; `x64-windows-static-md` |
| nv-codec-headers | `n13.1.15.0`, <https://github.com/FFmpeg/nv-codec-headers.git> |
| libvpl | `v2.10.2`, <https://github.com/intel/libvpl.git> |
| AMF | `v1.5.2`, <https://github.com/GPUOpen-LibrariesAndSDKs/AMF.git> |
| libdrm | `2.4.134`, `https://dri.freedesktop.org/libdrm/libdrm-2.4.134.tar.xz` |
| libva | `2.24.1`, `https://github.com/intel/libva/archive/refs/tags/2.24.1.tar.gz` |
| Linux Vulkan-Headers | `v1.4.362`, <https://github.com/KhronosGroup/Vulkan-Headers.git> |
| Windows Vulkan-Headers | vcpkg baseline above selects `1.4.357`; preserve dynamic loader/no static Vulkan/D3D12 DLL imports |
| Windows libvpx | `1.12.0`, vcpkg baseline `4d73751b3428ef49a7ac5d5df696b92e302de993` |

Retained FFmpeg recipe release tag: `vendored-ffmpeg-9.0.1`; asset names:

- `ffmpeg-9.0.1-win64-msvc-static-md-lgpl-minimal-d3d12-vulkan-h264dec-aac.zip`
- `ffmpeg-9.0.1-linux64-lgpl-shared-minimal-vaapi-vulkan-h264dec-aac.tar.xz`
- `ffmpeg-9.0.1-macos-arm64-lgpl-shared-h264dec-aac.tar.xz`

libvpx release tag: `vendored-libvpx-1.12.0`; asset:
`libvpx-1.12.0-win64-msvc.zip`.

Preserve `.github/ffmpeg-patches/` byte for byte. In the retained R3 recipes,
Windows applies our patches plus the pinned vcpkg port's patch list; Linux applies
our patches in filename order; macOS applies none. This is a statement about
those recipes, not verified provenance of the current upstream assets. The
complete configure options, overlay port injection, pkg-config fixes, library
packing and symbol/import checks remain in Git as `vendor-ffmpeg-windows.yml`,
`vendor-ffmpeg-macos.yml` and `vendor-libvpx-windows.yml`; see the
[historical source index](#historical-workflow-sources).
They enable only the intended LGPL components, including the H.264 decoder and
AAC encoder; do not replace them with a generic system FFmpeg. macOS dylibs target
14.0, use `@rpath` and VideoToolbox, and disable autodetection/Homebrew leakage.

## Packaging and signing

### Current local artifacts

The owner's current decision is **Windows unsigned, Linux unsigned, macOS
signed**. Windows EXE/MSI and Linux outputs do not require signing credentials,
Windows certificate provisioning or GPG sidecar generation for this local build.
Preserve version/asset naming, Windows VERSIONINFO, MSI ProductVersion mapping,
daemon/companion package separation and third-party DLL bytes/signatures.
`cargo wix --no-build` packages the already-built payload; it does not imply a
requirement to sign the current Windows artifacts. No updater trust check is
changed by this build policy.

For macOS, retain inside-out signing of dylibs, executables, app and package,
hardened-runtime entitlements, Developer ID Application/Installer identities,
complete Apple prerequisites, notarytool, stapler and `spctl` checks as applicable
to the selected package. Use existing `scripts/macos-productbuild-gated.sh` for
nonrelocatable packaging and the minimum-OS gate. Desktop/setup resources remain
`agents/meshharbor-{desktop,setup}/icons/icon.png`. Re-extract the packaged app and
verify its signature/notarization. The migration itself performed no signing.

### Historical signed distribution and unchanged updater checks

[Code signing](code-signing.md), `scripts/signing/README.md` and the
[historical source index](#historical-workflow-sources) retain the former official
distribution recipes. They do **not**
require Windows/Linux signing for the owner's current local artifacts. In that
historical signed path, Windows payload signing preceded MSI packaging, a relink
invalidated signatures, and publisher/timestamp/chain verification used `G ROX
LTD`; vendor DLLs kept their original signatures. Linux/macOS updater assets used
required `.asc` sidecars against the pinned GPG key. Those existing updater trust
checks have not been removed or weakened. **Unsigned Linux artifacts must not
be claimed to pass the existing upgrade path that requires `.asc` verification.**
Unsigned Windows artifacts likewise are not claimed compatible with the existing
signed update path. Local packaging does not disable either verifier. A SHA
sidecar alone is not a trust anchor.

`scripts/signing/90-verify-release.{sh,ps1}` checks the historical signed release
contract and may read the network. It is not a syntax-only check or the pass/fail
oracle for the intentionally unsigned Windows/Linux local outputs. Publishing
any `agent-v*` pre-release can reach the fleet; this local preparation publishes
nothing. Agent/setup artifacts should identify the same intended source revision;
no tag dispatch builds or releases them.

## Offline LGPL source offer

Keep existing public source offers available; removing CI must not retract them.
See [the written offer](../THIRD-PARTY-NOTICES.md) and [relinking](lgpl-relink.md).
The LGPL assembly recipe needs upstream source, **both** patch sets, exact
vcpkg baseline and complete vendor configure/build recipes, not just a URL.

The upstream Windows asset/patch discrepancy above must be resolved before
claiming a corresponding-source mapping. This assembler cannot turn a guessed
build revision into evidence for those binaries. The patch-matching revision
`189edfae429307c97e77e1713ca4628e9687ee3b` was absent from the NOCI Git
database during this migration’s verification and is **not established as the
vendor build commit**. Patch matching alone does not establish the full build or release provenance.

The offline assembler requires Python **3.11+** and supports the historical
**n9.0.1** recipe family. Provide
an explicit complete local **build repository** and the **actual vendor build
commit** it contains, not a guessed agent commit or the current branch. The build
repository may be separate from this application checkout; all historical recipe
and patch reads use that repository. Also provide the independently verified
upstream archive and a local vcpkg repository containing its pinned baseline.
It fails if the historical blobs/pin are absent,
the archive hash mismatches, the port contains unsupported entries, or output
already exists. Partial/promisor repositories are rejected; missing objects must
not trigger a lazy fetch. Git replace objects are ignored. It never downloads,
uploads, signs or changes system state.

```sh
python3 scripts/lgpl-source-offer-local.py \
  --build-repo <complete-local-original-build-git-repository> \
  --build-ref <full-actual-vendor-build-commit> \
  --ffmpeg-source <verified-ffmpeg-n9.0.1.tar.gz> \
  --ffmpeg-sha256 <independently-verified-sha256> \
  --vcpkg-repo <local-vcpkg-git-repository> \
  --output <new-exclusive-output-directory>
```

Offline regression: `python3 scripts/test-lgpl-source-offer-local.py` creates two
independent temporary Git repositories and a synthetic archive, checks positive
assembly and fail-closed cases, then removes only that temporary fixture. It
performs no network access and does not validate real published asset provenance.

Output includes `bundle/`, `SOURCE-INPUTS.json`,
`ffmpeg-n9.0.1-corresponding-source.tar.xz`, its `.sha256` and
`ffmpeg-n9.0.1-corresponding-source.inputs.txt`. Historical workflow bytes are
included **inside the offer as original build inputs**, never reinstalled as CI.
The inputs manifest retains the old patch/baseline/recipe hash layout. Archive
members are read back and hashed. `SOURCE-INPUTS.json` explicitly records that
binary provenance is not verified and no publication occurred. The old workflow
recipe is retrievable from Git, but local assembly does not prove a released
binary was produced from it. Independently establish that mapping before release.

For changed local vendor recipes/versions, review and extend the assembler and
manifest contract first; it intentionally refuses to guess new mappings.
Before publishing, compare library patch manifests and source-offer inputs to
the **actual** vendor inputs, verify application source/relinkability and publish
all required offer assets with sufficient retention. There is no automatic
release gate now. No legal-compliance or end-to-end build claim follows from
this migration or a successful local assembly alone.

## Images and historical recipes

`Dockerfile` remains the local image recipe (`PROFILE=full`, hosted `SAAS=1`,
selfhost `SAAS=0`). `Dockerfile.hive-archive` and its existing entrypoint remain.
Run `cd ui && bun docs/dates.ts --write` with full Git history before an image
build that needs dates. Builds, registry pushes and GitOps/ArgoCD deployment
are separate authorized operations. Do not automatically prune images, caches,
registry tags or user toolchains on a developer host.

Existing source offers retain their original recipes. Historical FR documents
and incident evidence remain unchanged; they do not authorize CI.

## Historical workflow sources

Retired automation is kept in Git history, not copied into an executable local
runbook. Inspect an original workflow with
`git show 3c48d7e7:.github/workflows/<name>.yml` (replace `<name>` with its stem),
for example:

```sh
git show 3c48d7e7:.github/workflows/release-agent.yml
```

The 23 original filenames are:

- `cache-janitor.yml`
- `ci.yml`
- `cla.yml`
- `daily-health-check.yml`
- `fr-verification-debt.yml`
- `ghcr-retention.yml`
- `hive-archive-image.yml`
- `hosted-image.yml`
- `installer-smoke.yml`
- `integration-tests.yml`
- `lgpl-source-offer.yml`
- `licensing.yml`
- `macos-mesh-test.yml`
- `promote.yml`
- `publish-selfhost-image.yml`
- `release-agent.yml`
- `release-setup.yml`
- `release-tunnel.yml`
- `seed-release-caches.yml`
- `ui-phone-smoke.yml`
- `vendor-ffmpeg-macos.yml`
- `vendor-ffmpeg-windows.yml`
- `vendor-libvpx-windows.yml`

Retired composite-action sources can likewise be inspected with
`git show 3c48d7e7:.github/actions/<name>/action.yml`. The original names were
`cargo-cache-salt`, `ci-linux-system-deps`, `ci-seed-restore`, `ci-seed-save`,
`seed-cache-restore`, `seed-cache-save`, `sign-windows` and `sign-macos`.

These sources contain runner placeholders, credential provisioning, signing,
cache deletion, uploading and deployment operations. They are historical evidence,
not current local commands or authority to perform those operations. Current
Windows/Linux local artifacts remain unsigned, and only macOS is signed. A
historical R3 recipe alone does not prove which source produced an upstream
vendor binary; the offline source offer still requires its actual build repository
and revision, original inputs and verified mapping.
