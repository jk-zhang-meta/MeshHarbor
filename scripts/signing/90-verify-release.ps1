# 90-verify-release.ps1 -- download every asset of a published release and
# assert it is actually signed. Exits non-zero if anything is not.
#
#   pwsh scripts/signing/90-verify-release.ps1 -Tag agent-v0.3.0-rc.361
#   pwsh scripts/signing/90-verify-release.ps1 -Tag setup-v0.3.0-rc.266 -KeepFiles
#   pwsh scripts/signing/90-verify-release.ps1 -Latest agent
#
# This exists because signedness was, for the entire history of this repo,
# inferred from whether a SECRET WAS SET rather than from the bytes -- so
# every release advertised its signing state without ever checking it.
# This script checks the bytes.
#
# What it verifies per asset type:
#   .msi  chain (signtool verify /pa /all), RFC3161 timestamp, subject, AND
#         the payload EXEs inside (extracted via an administrative install) --
#         an MSI whose wrapper is signed but whose payload is not still drops
#         unsigned binaries onto disk, which is what AV and AppLocker see
#   .exe  chain, timestamp, subject
#   .pkg  reported only; run the .sh variant on a Mac for pkgutil/spctl
#   *     GitHub build provenance attestation, and a .asc detached signature
#         when one was published
#
# Windows-only for the Authenticode half. Run 90-verify-release.sh on macOS
# for the Gatekeeper half.

[CmdletBinding()]
param(
    [string]$Tag = '',
    [ValidateSet('agent', 'setup', 'tunnel')]
    [string]$Latest = '',
    [string]$Repo = '',
    [string]$ExpectSubject = '',
    [switch]$KeepFiles,
    # Old releases predate signing; use this to inventory them without
    # turning the whole run red.
    [switch]$WarnOnly
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
if (-not $Repo)          { $Repo          = Get-StateValue $state 'repo' $script:DefaultRepo }
if (-not $ExpectSubject) { $ExpectSubject = Get-StateValue $state 'certificateSubject' '' }
if ($ExpectSubject -match 'CN=([^,]+)') { $ExpectSubject = $Matches[1].Trim() }

Require-Command 'gh' 'Install: https://cli.github.com/' | Out-Null

if (-not $Tag) {
    if (-not $Latest) { Fail 'pass -Tag <tag> or -Latest agent|setup|tunnel' }
    $prefix = "$Latest-v"
    $tags = & gh release list --repo $Repo --limit 100 --json tagName --jq '.[].tagName' |
            Where-Object { $_ -like "$prefix*" }
    $Tag = $tags | Select-Object -First 1
    if (-not $Tag) { Fail "no release found with prefix '$prefix' on $Repo" }
    Info "resolved -Latest $Latest -> $Tag"
}

$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Warn 'signtool.exe not found -- falling back to Get-AuthenticodeSignature only (no chain policy check).' }

$stage = Join-Path ([IO.Path]::GetTempPath()) ("meshharbor-verify-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Say "Downloading $Tag from $Repo"
& gh release download $Tag --repo $Repo --dir $stage --clobber
if ($LASTEXITCODE -ne 0) { Fail "could not download release $Tag" }
$assets = Get-ChildItem $stage -File | Where-Object { $_.Name -notlike '*.sha256' -and $_.Name -notlike '*.asc' }
Ok "$($assets.Count) asset(s)"

$failures = New-Object System.Collections.Generic.List[string]
$notes    = New-Object System.Collections.Generic.List[string]

function Test-Authenticode {
    param([string]$Path, [string]$Label)

    $sig = Get-AuthenticodeSignature $Path
    $name = Split-Path -Leaf $Path

    if ($sig.Status -eq 'NotSigned') {
        $failures.Add("$Label UNSIGNED: $name")
        Write-Host "      UNSIGNED  $name" -ForegroundColor Red
        return
    }
    if ($sig.Status -ne 'Valid') {
        $failures.Add("$Label signature status '$($sig.Status)': $name")
        Write-Host "      $($sig.Status)  $name" -ForegroundColor Red
        return
    }

    $subject = $sig.SignerCertificate.Subject
    $cn = if ($subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $subject }

    if ($signtool) {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $signtool.FullName verify /pa /all /q $Path 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) {
            $failures.Add("$Label failed 'signtool verify /pa /all': $name")
            Write-Host "      CHAIN FAIL  $name" -ForegroundColor Red
            return
        }
    }

    # Artifact Signing certificates live about three days. Without an
    # RFC3161 countersignature the signature stops validating almost
    # immediately after release, which looks exactly like tampering.
    if (-not $sig.TimeStamperCertificate) {
        $failures.Add("$Label has NO RFC3161 timestamp: $name")
        Write-Host "      NO TIMESTAMP  $name  ($cn)" -ForegroundColor Red
        return
    }

    if ($ExpectSubject -and $cn -notlike "*$ExpectSubject*") {
        $failures.Add("$Label subject '$cn' does not contain '$ExpectSubject': $name")
        Write-Host "      WRONG SUBJECT  $name  ($cn)" -ForegroundColor Red
        return
    }

    Write-Host "      OK  $name" -ForegroundColor Green
    Info "          subject: $cn"
    Info "          expires: $($sig.SignerCertificate.NotAfter)  (timestamped, so this is not a cliff)"
}

foreach ($a in $assets) {
    Write-Host ''
    Say $a.Name
    $ext = $a.Extension.ToLower()

    switch ($ext) {
        '.msi' {
            Test-Authenticode -Path $a.FullName -Label 'MSI'

            # The wrapper being signed says nothing about what lands on disk.
            # An administrative install extracts the payload without touching
            # the machine (no service, no registry, no reboot).
            $extract = Join-Path $stage ("extract-" + $a.BaseName)
            New-Item -ItemType Directory -Path $extract -Force | Out-Null
            $p = Start-Process msiexec -ArgumentList @('/a', "`"$($a.FullName)`"", '/qn', "TARGETDIR=`"$extract`"") -Wait -PassThru
            if ($p.ExitCode -ne 0) {
                Warn "  could not extract payload (msiexec exit $($p.ExitCode)); payload not verified"
                $notes.Add("payload of $($a.Name) not verified (extract failed)")
            } else {
                $payload = Get-ChildItem $extract -Recurse -Include '*.exe', '*.dll' -File
                Info "  payload: $($payload.Count) binaries"
                foreach ($f in $payload) {
                    if ($f.Name -ieq 'wintun.dll') {
                        # Third-party and deliberately NOT re-signed: replacing
                        # WireGuard LLC's signature would break AV allow-lists
                        # keyed to their publisher.
                        $ws = Get-AuthenticodeSignature $f.FullName
                        $wcn = if ($ws.SignerCertificate.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { '<none>' }
                        if ($ws.Status -eq 'Valid' -and $wcn -like '*WireGuard*') {
                            Write-Host "      OK  wintun.dll (third-party: $wcn)" -ForegroundColor Green
                        } else {
                            $failures.Add("wintun.dll in $($a.Name) is not WireGuard-signed (status=$($ws.Status), cn=$wcn) -- did something re-sign it?")
                            Write-Host "      WRONG SIGNER  wintun.dll ($wcn)" -ForegroundColor Red
                        }
                        continue
                    }
                    Test-Authenticode -Path $f.FullName -Label "payload of $($a.Name)"
                }
            }
        }
        '.exe' { Test-Authenticode -Path $a.FullName -Label 'EXE' }
        '.zip' {
            $unzip = Join-Path $stage ("unzip-" + $a.BaseName)
            Expand-Archive -Path $a.FullName -DestinationPath $unzip -Force
            $inner = Get-ChildItem $unzip -Recurse -Include '*.exe' -File
            if ($inner.Count -eq 0) { Warn '  no EXE inside the zip'; $notes.Add("no EXE inside $($a.Name)") }
            foreach ($f in $inner) { Test-Authenticode -Path $f.FullName -Label "inside $($a.Name)" }
        }
        '.pkg' {
            Warn '  macOS package -- run 90-verify-release.sh on a Mac for pkgutil / stapler / spctl'
            $notes.Add("$($a.Name) needs the macOS verifier")
        }
        default {
            Info '  no Authenticode expectation for this type'
        }
    }

    # Detached GPG signature, when one was published alongside.
    $asc = "$($a.FullName).asc"
    if (Test-Path $asc) {
        if (Get-Command gpg -ErrorAction SilentlyContinue) {
            $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            & gpg --verify $asc $a.FullName 2>&1 | Out-Null
            $code = $LASTEXITCODE
            $ErrorActionPreference = $prev
            if ($code -eq 0) { Write-Host '      OK  detached GPG signature' -ForegroundColor Green }
            else { $failures.Add("GPG signature invalid: $($a.Name)"); Write-Host '      GPG INVALID' -ForegroundColor Red }
        } else { Info '  .asc present but gpg is not installed' }
    }

    # Build provenance. Independent of the asset type and of GitHub's own
    # `digest` field.
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & gh attestation verify $a.FullName --repo $Repo 2>&1 | Out-Null
    $attCode = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($attCode -eq 0) { Write-Host '      OK  build provenance attestation' -ForegroundColor Green }
    else { $notes.Add("no build provenance attestation for $($a.Name)") }
}

Write-Host ''
Write-Host ('-' * 60)
if ($notes.Count -gt 0) {
    Say 'Notes'
    foreach ($n in $notes) { Info "  - $n" }
}

if ($failures.Count -eq 0) {
    Write-Host ''
    Write-Host "RELEASE $Tag VERIFIED" -ForegroundColor Green
    if (-not $KeepFiles) { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    exit 0
}

Write-Host ''
Write-Host "RELEASE $Tag FAILED VERIFICATION" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
if ($KeepFiles) { Info ''; Info "artifacts kept at $stage" }
else { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
if ($WarnOnly) { exit 0 }
exit 1
