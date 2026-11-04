<#
.SYNOPSIS
  Stage the vendored Windows FFmpeg (static-md, LGPL, minimal) and libvpx
  trees on a dev box so `cargo build -p meshharbord --features ffmpeg-encoder,vp9-444`
  works NATIVELY, against exactly the bytes the release workflow links.

.DESCRIPTION
  FR-77 P0. Until now the only proven local loop for the FFmpeg backend was
  the WSL recipe; on Windows `cargo check --features ffmpeg-encoder` panicked
  in ffmpeg-sys-next's build script because no FFmpeg was installed. This
  script reproduces release-agent.yml's "Fetch vendored FFmpeg" step on a
  developer machine:

    1. downloads the vendored FFmpeg zip (+ .sha256, verified) and the
       vendored libvpx zip from the repo's GitHub releases,
    2. extracts them under $Root (default C:\ffmpeg-pin, the same path CI
       uses, so a workflow snippet pasted from the YAML works unchanged),
    3. rewrites the `prefix=` line of every .pc file to the real location
       (the vendor machine's prefix is baked in),
    4. provides a pkg-config: vcpkg's `pkgconf` renamed to pkg-config.exe,
       exactly as the workflow does,
    5. prints the environment to set and the build + smoke commands.

  Nothing here is shipped. The FFmpeg CLI for experiments is a separate
  thing (`winget install Gyan.FFmpeg`); this stages LIBRARIES + headers.

.PARAMETER Env
  Print ONLY the `$env:` assignments, so a caller can `Invoke-Expression`
  the output in its own session.

.EXAMPLE
  pwsh scripts/dev-ffmpeg-windows.ps1
  # then, in a "x64 Native Tools" shell (vcvars64 — bindgen wants MSVC's stdint.h):
  Invoke-Expression (pwsh scripts/dev-ffmpeg-windows.ps1 -Env | Out-String)
  cargo build -p meshharbord --release --features "full-hw,vp9-444,system-context,ffmpeg-encoder,overlay-l3,overlay-netstack,ssh-server"
  .\target\release\roomlerd.exe encoder-smoke --encoder hardware --codec hevc

.NOTES
  Rollback to the previous FFmpeg: -FfmpegRelease vendored-ffmpeg-8.1.2
  -FfmpegAsset ffmpeg-8.1.2-win64-msvc-static-md-lgpl-minimal.zip
#>
[CmdletBinding()]
param(
  [string]$FfmpegRelease = 'vendored-ffmpeg-9.0.1',
  [string]$FfmpegAsset   = 'ffmpeg-9.0.1-win64-msvc-static-md-lgpl-minimal-d3d12-vulkan-h264dec-aac.zip',
  [string]$LibvpxRelease = 'vendored-libvpx-1.12.0',
  [string]$LibvpxAsset   = 'libvpx-1.12.0-win64-msvc.zip',
  [string]$Root          = 'C:\ffmpeg-pin',
  [string]$Repo          = 'gjovanov/roomler-ai',
  [string]$Vcpkg         = 'C:\dev\vcpkg',
  [switch]$Env,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

$ffRoot  = Join-Path $Root 'installed\x64-windows-static-md'
$vpxRoot = Join-Path $Root 'libvpx'
$binDir  = Join-Path $Root 'bin'
$dlDir   = Join-Path $Root 'downloads'

function Write-Step($msg) { if (-not $Env) { Write-Host "==> $msg" -ForegroundColor Cyan } }

# ── 0. Fast path: everything already staged ───────────────────────────────
$stamp = Join-Path $Root "staged-$FfmpegAsset.txt"
$ready = (Test-Path $stamp) -and (Test-Path (Join-Path $ffRoot 'lib\pkgconfig\libavcodec.pc')) -and -not $Force

if (-not $ready) {
  if ($Env) { throw "nothing staged under $Root yet — run without -Env first" }
  foreach ($d in @($Root, $dlDir, $binDir)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

  # ── 1. Download + verify ────────────────────────────────────────────────
  Write-Step "downloading $FfmpegAsset from release $FfmpegRelease"
  Remove-Item (Join-Path $dlDir "$FfmpegAsset*") -ErrorAction SilentlyContinue
  gh release download $FfmpegRelease --repo $Repo --pattern "$FfmpegAsset*" --dir $dlDir
  if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $FfmpegRelease / $FfmpegAsset" }
  $zip = Join-Path $dlDir $FfmpegAsset
  $sha = Join-Path $dlDir "$FfmpegAsset.sha256"
  if (Test-Path $sha) {
    $want = ((Get-Content $sha -Raw) -split '\s+')[0].ToLower()
    $have = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if ($want -ne $have) { throw "sha256 mismatch for ${FfmpegAsset}: expected $want got $have" }
    Write-Step "sha256 verified ($have)"
  } else {
    Write-Warning "no .sha256 sidecar on the release for $FfmpegAsset — proceeding unverified"
  }

  Write-Step "downloading $LibvpxAsset from release $LibvpxRelease"
  Remove-Item (Join-Path $dlDir "$LibvpxAsset*") -ErrorAction SilentlyContinue
  gh release download $LibvpxRelease --repo $Repo --pattern "$LibvpxAsset*" --dir $dlDir
  if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $LibvpxRelease / $LibvpxAsset" }

  # ── 2. Extract into the CI layout ───────────────────────────────────────
  Write-Step "extracting FFmpeg into $ffRoot"
  if (Test-Path $ffRoot) { Remove-Item -Recurse -Force $ffRoot }
  New-Item -ItemType Directory -Path $ffRoot -Force | Out-Null
  Expand-Archive -Path $zip -DestinationPath $ffRoot -Force
  # The zip carries lib/ + include/ (+ ROOMLER-PATCHES.txt) at its top level,
  # or one wrapping directory — normalise to $ffRoot\lib.
  if (-not (Test-Path (Join-Path $ffRoot 'lib'))) {
    $inner = Get-ChildItem $ffRoot -Directory | Select-Object -First 1
    if ($inner -and (Test-Path (Join-Path $inner.FullName 'lib'))) {
      Get-ChildItem $inner.FullName | Move-Item -Destination $ffRoot -Force
      Remove-Item -Recurse -Force $inner.FullName
    }
  }
  if (-not (Test-Path (Join-Path $ffRoot 'lib\pkgconfig\libavcodec.pc'))) { throw "no lib\pkgconfig\libavcodec.pc under $ffRoot after extraction" }

  Write-Step "extracting libvpx into $vpxRoot"
  if (Test-Path $vpxRoot) { Remove-Item -Recurse -Force $vpxRoot }
  New-Item -ItemType Directory -Path $vpxRoot -Force | Out-Null
  Expand-Archive -Path (Join-Path $dlDir $LibvpxAsset) -DestinationPath $vpxRoot -Force

  # ── 3. Fix the baked-in prefixes ────────────────────────────────────────
  # pkgconf on Windows wants forward slashes in .pc paths.
  $ffPrefix = ($ffRoot -replace '\\', '/')
  foreach ($pc in Get-ChildItem (Join-Path $ffRoot 'lib\pkgconfig') -Filter '*.pc') {
    $c = Get-Content $pc.FullName -Raw
    $c = [regex]::Replace($c, '(?m)^prefix=.*$', "prefix=$ffPrefix")
    Set-Content -Path $pc.FullName -Value $c -Encoding ascii -NoNewline
  }
  $vpxPc = Get-ChildItem $vpxRoot -Recurse -Filter 'vpx.pc' | Select-Object -First 1
  if (-not $vpxPc) { throw "vpx.pc not found under $vpxRoot" }
  $vpxPrefixDir = (Split-Path (Split-Path $vpxPc.DirectoryName -Parent) -Parent)   # <prefix>/lib/pkgconfig/vpx.pc
  $vpxPrefix = ($vpxPrefixDir -replace '\\', '/')
  $c = Get-Content $vpxPc.FullName -Raw
  $c = [regex]::Replace($c, '(?m)^prefix=.*$', "prefix=$vpxPrefix")
  Set-Content -Path $vpxPc.FullName -Value $c -Encoding ascii -NoNewline
  Set-Content -Path (Join-Path $Root 'libvpx-pkgconfig.txt') -Value $vpxPc.DirectoryName -Encoding ascii -NoNewline

  Set-Content -Path $stamp -Value (Get-Date -Format o) -Encoding ascii -NoNewline
  Write-Step "staged: $ffRoot (FFmpeg) + $vpxRoot (libvpx) + $binDir\pkg-config.exe"
  if (Test-Path (Join-Path $ffRoot 'ROOMLER-PATCHES.txt')) {
    Write-Step "vendored FFmpeg carries roomler patches:"; Get-Content (Join-Path $ffRoot 'ROOMLER-PATCHES.txt')
  }
}

# ── 4. pkg-config = vcpkg's pkgconf, renamed (what the workflow does) ───────
# Runs every time and is idempotent. pkgconf.exe needs its sibling
# pkgconf-N.dll, so the WHOLE tool dir is copied, and the result is proven by
# running it: a lone copied exe exits 0xC0000135 (DLL not found), which the
# cargo build reports only as "pkg-config exited with status code -1073741515".
$pkgExe = Join-Path $binDir 'pkg-config.exe'
$works = $false
if (Test-Path $pkgExe) { & $pkgExe --version *> $null; $works = ($LASTEXITCODE -eq 0) }
if (-not $works) {
  if ($Env) { throw "no working pkg-config under $binDir — run without -Env first" }
  New-Item -ItemType Directory -Path $binDir -Force | Out-Null
  $toolDir = Join-Path $Vcpkg 'installed\x64-windows\tools\pkgconf'
  if (-not (Test-Path (Join-Path $toolDir 'pkgconf.exe'))) {
    Write-Step "installing pkgconf via vcpkg ($Vcpkg)"
    & (Join-Path $Vcpkg 'vcpkg.exe') install pkgconf:x64-windows
    if ($LASTEXITCODE -ne 0) { throw "vcpkg install pkgconf:x64-windows failed" }
  }
  Get-ChildItem $toolDir -File | ForEach-Object { Copy-Item $_.FullName (Join-Path $binDir $_.Name) -Force }
  Copy-Item (Join-Path $toolDir 'pkgconf.exe') $pkgExe -Force
  & $pkgExe --version *> $null
  if ($LASTEXITCODE -ne 0) { throw "staged pkg-config.exe does not run (exit $LASTEXITCODE) — check the DLLs next to it in $binDir" }
  Write-Step "pkg-config staged: $pkgExe (pkgconf $(& $pkgExe --version))"
}

# ── 5. The environment ────────────────────────────────────────────────────
$vpxPkg = Get-Content (Join-Path $Root 'libvpx-pkgconfig.txt') -Raw
# Deliberately NO FFMPEG_DIR: when it is set, ffmpeg-sys-next's build script
# takes the include/lib dirs from it and never asks pkg-config, so the extra
# libraries the vendored .pc files carry (`-lvpl -ladvapi32 -lole32 …`) are
# never linked and the build dies at link time with every `MFX*` symbol
# unresolved. The workflow sets only PKG_CONFIG_PATH on Windows for the same
# reason; FFMPEG_DIR is a Linux/macOS convenience for the SHARED trees.
$lines = @(
  "`$env:PKG_CONFIG_PATH = '$(Join-Path $ffRoot 'lib\pkgconfig');$vpxPkg'",
  "`$env:PKG_CONFIG_ALLOW_SYSTEM_LIBS = '1'",
  "`$env:PATH = '$binDir;' + `$env:PATH",
  # audiopus_sys builds its bundled libopus with CMake, whose CMakeLists says
  # cmake_minimum_required(< 3.5); CMake 3.31+ refuses that outright. Same
  # workaround release-agent.yml carries for the `audio` feature.
  "`$env:CMAKE_POLICY_VERSION_MINIMUM = '3.5'",
  # ffmpeg-sys-next's bindgen needs libclang; the LLVM installer's default path.
  "if (-not `$env:LIBCLANG_PATH -and (Test-Path 'C:\Program Files\LLVM\bin')) { `$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin' }"
)
if ($Env) { $lines | ForEach-Object { Write-Output $_ }; exit 0 }

Write-Host ""
Write-Host "Set this in a 'x64 Native Tools Command Prompt' / vcvars64 PowerShell (bindgen needs MSVC's stdint.h):" -ForegroundColor Yellow
$lines | ForEach-Object { Write-Host "  $_" }
Write-Host ""
Write-Host "Or in one go:  Invoke-Expression (pwsh scripts/dev-ffmpeg-windows.ps1 -Env | Out-String)"
Write-Host ""
Write-Host "Then (the MSI's exact feature set; never vp9-444-bindgen on Windows):"
Write-Host '  cargo build -p meshharbord --release --features "full-hw,vp9-444,system-context,ffmpeg-encoder,overlay-l3,overlay-netstack,ssh-server"'
Write-Host '  .\target\release\roomlerd.exe encoder-smoke --encoder hardware --codec hevc'
Write-Host '  .\target\release\roomlerd.exe encoder-smoke --encoder hardware --codec av1'
