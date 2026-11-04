# 40-smoke-sign.ps1 -- prove the certificate profile + RBAC actually work by
# signing a throwaway PE from this machine, BEFORE spending a CI run on it.
#
#   pwsh scripts/signing/40-smoke-sign.ps1
#
# Authenticates with DefaultAzureCredential, so an `az login` session is
# enough. If this succeeds, the only thing standing between you and signed
# releases is the OIDC wiring (30-github-oidc.ps1) -- which this script
# deliberately does NOT exercise, so a failure here is unambiguous.
#
# Bootstraps the Trusted Signing dlib from nuget.org into a cache dir; no
# .NET SDK required (a .nupkg is a zip).

[CmdletBinding()]
param(
    [string]$File = '',
    [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com',
    [string]$CacheDir = ''
)

. "$PSScriptRoot\_common.ps1"

$state    = Read-State
$endpoint = Get-StateValue $state 'endpoint'
$account  = Get-StateValue $state 'accountName'
$profile  = Get-StateValue $state 'profileName'
if (-not $endpoint -or -not $account -or -not $profile) {
    Fail 'missing state. Run 00-preflight.ps1, 10-azure-provision.ps1 and 20-azure-cert-profile.ps1 first.'
}
if (-not $CacheDir) { $CacheDir = Join-Path $env:LOCALAPPDATA 'roomler-signing-tools' }

# --------------------------------------------------------------- signtool
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) {
    Fail 'signtool.exe not found. Install the Windows 10/11 SDK (Signing Tools component).'
}
Ok "signtool: $($signtool.FullName)"

# ------------------------------------------------------------------- dlib
Say 'Trusted Signing dlib'
$pkgId = 'microsoft.trusted.signing.client'
New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null

$index = Invoke-RestMethod -Uri "https://api.nuget.org/v3-flatcontainer/$pkgId/index.json" -UseBasicParsing
$version = ($index.versions | Where-Object { $_ -notmatch '-' } | Select-Object -Last 1)
if (-not $version) { $version = $index.versions[-1] }
Info "  version $version"

$pkgDir = Join-Path $CacheDir "$pkgId.$version"
if (-not (Test-Path (Join-Path $pkgDir 'bin'))) {
    $nupkg = Join-Path $CacheDir "$pkgId.$version.nupkg"
    $zip   = "$nupkg.zip"
    Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/$pkgId/$version/$pkgId.$version.nupkg" `
                      -OutFile $nupkg -UseBasicParsing
    Copy-Item $nupkg $zip -Force
    Expand-Archive -Path $zip -DestinationPath $pkgDir -Force
    Remove-Item $zip -Force
    Ok "downloaded + expanded to $pkgDir"
} else {
    Ok "cached at $pkgDir"
}

$dlib = Get-ChildItem -Path $pkgDir -Recurse -Filter 'Azure.CodeSigning.Dlib.dll' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if (-not $dlib) {
    $dlib = Get-ChildItem -Path $pkgDir -Recurse -Filter '*.Dlib.dll' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
}
if (-not $dlib) { Fail "no x64 signing dlib found under $pkgDir" }
Ok "dlib: $($dlib.FullName)"

# --------------------------------------------------------------- metadata
$meta = [ordered]@{
    Endpoint               = $endpoint
    CodeSigningAccountName = $account
    CertificateProfileName = $profile
}
$metaPath = Join-Path $CacheDir 'roomler-signing-metadata.json'
($meta | ConvertTo-Json) | Set-Content -Path $metaPath -Encoding ascii
Ok "metadata: $metaPath"

# ------------------------------------------------------------ target file
$stage = Join-Path ([IO.Path]::GetTempPath()) ("roomler-signsmoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
if (-not $File) {
    # Prefer a REAL project binary over a Windows system EXE. System EXEs are
    # catalog-signed: even after our signature is embedded, catalog matching
    # takes precedence in Get-AuthenticodeSignature, so the readout below
    # reports "CN=Microsoft Windows" instead of the actual signer (verified
    # the hard way, 2026-08-22). A roomler build has no catalog entry.
    $candidates = @(
        (Join-Path $PSScriptRoot '..\..\target\release\meshharbor.exe'),
        (Join-Path $PSScriptRoot '..\..\target\release\meshharbord.exe'),
        (Join-Path $PSScriptRoot '..\..\target\debug\meshharbor.exe')
    )
    $src = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    $File = Join-Path $stage 'smoke-target.exe'
    if ($src) {
        Copy-Item $src $File -Force
        Info "  target: a throwaway copy of $src"
    } else {
        Copy-Item (Join-Path $env:WINDIR 'System32\where.exe') $File -Force
        Warn 'no roomler build found under target/ -- falling back to a system-EXE copy.'
        Warn 'The signature will be REAL, but the subject readout below will show the'
        Warn 'CATALOG signer (Microsoft), not ours. Build any roomler binary first for'
        Warn 'a faithful readout, or pass -File <path-to-unsigned.exe>.'
    }
} else {
    $copy = Join-Path $stage (Split-Path -Leaf $File)
    Copy-Item $File $copy -Force
    $File = $copy
    Info "  target: $File"
}

# ------------------------------------------------------------------- sign
Say 'Signing'
Info '  auth: DefaultAzureCredential (your `az login` session)'
& $signtool.FullName sign /v /debug `
    /fd SHA256 `
    /tr $TimestampUrl /td SHA256 `
    /dlib $dlib.FullName `
    /dmdf $metaPath `
    $File
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Fail @'
signing failed. Most likely causes, in order:
  * the identity validation is not Completed yet (15-azure-identity-status.ps1)
  * your account lacks "Artifact Signing Certificate Profile Signer" on the
    profile -- 30-github-oidc.ps1 grants it to the CI principal, not to you;
    assign it to yourself too if you want to sign locally
  * the endpoint region does not match the account region
'@
}

# ----------------------------------------------------------------- verify
Say 'Verifying'
& $signtool.FullName verify /pa /all /v $File
if ($LASTEXITCODE -ne 0) { Fail 'signtool verify failed -- the signature did not validate against the machine trust store.' }

$sig = Get-AuthenticodeSignature $File
Write-Host ''
Ok "Status:  $($sig.Status)"
Ok "Subject: $($sig.SignerCertificate.Subject)"
Ok "Issuer:  $($sig.SignerCertificate.Issuer)"
Ok "Expires: $($sig.SignerCertificate.NotAfter)"
if ($sig.TimeStamperCertificate) {
    Ok "Timestamped by: $($sig.TimeStamperCertificate.Subject)"
} else {
    Warn 'NO RFC3161 timestamp. Artifact Signing certificates live ~3 days --'
    Warn 'without a timestamp every signature expires almost immediately.'
}

if ($sig.SignerCertificate.Subject -match 'CN=([^,]+)') {
    # NEVER overwrite an existing certificateSubject: 20-azure-cert-profile is
    # the source of truth, and a catalog-signer readout here (see the fixture
    # note above) once polluted the state with "CN=Microsoft Windows".
    if (-not (Get-StateValue $state 'certificateSubject' '')) {
        $state = Set-StateValue $state 'certificateSubject' $sig.SignerCertificate.Subject
        Save-State $state
    }
    Write-Host ''
    Info "Windows will show: Verified publisher: $($Matches[1].Trim())"
}

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Ok 'SMOKE SIGN OK -- the profile and your rights are good.'
Info 'Next: pwsh scripts/signing/30-github-oidc.ps1 (if not done), then dispatch a workflow.'
