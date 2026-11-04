# 50-selfsigned-dev-cert.ps1 -- create a self-signed code-signing cert so the
# ENTIRE release pipeline can be rehearsed for free, before any money is
# spent and while Azure identity validation is still processing.
#
#   pwsh scripts/signing/50-selfsigned-dev-cert.ps1
#   pwsh scripts/signing/50-selfsigned-dev-cert.ps1 -Subject "CN=Example GmbH (DEV), O=Example GmbH, C=AT" -PushSecrets
#
# The sign-windows action's `local` mode is NOT a weaker code path: it
# imports this cert into the runner's Root + TrustedPublisher stores, so the
# identical `signtool verify /pa /all` strict check runs and passes. That is
# the whole point -- the free rehearsal genuinely exercises the Azure code
# path, only the key differs.
#
# This certificate is worthless to an attacker: nothing trusts it by default.
# It is still a private key -- the .pfx is written to a gitignored path and
# must never be committed.

[CmdletBinding()]
param(
    # Mirrors the shape of the real Azure subject (CN=G ROX LTD, O=G ROX LTD,
    # L=Pazardzhik, C=BG) but is clearly marked DEV so a rehearsal artifact
    # can never be mistaken for a shippable one.
    [string]$Subject  = 'CN=G ROX LTD (DEV), O=G ROX LTD, L=Pazardzhik, C=BG',
    [string]$OutDir   = '',
    [string]$Password = '',
    [int]$Years       = 3,
    [switch]$PushSecrets,
    [string]$Repo     = ''
)

. "$PSScriptRoot\_common.ps1"

if ($env:OS -ne 'Windows_NT') { Fail 'this script needs Windows (New-SelfSignedCertificate).' }

$state = Read-State
if (-not $Repo)   { $Repo   = Get-StateValue $state 'repo' $script:DefaultRepo }
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot 'dev-cert' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

if (-not $Password) {
    # Not a security boundary -- the cert is untrusted everywhere. Random
    # anyway so it never becomes a copy-pasted habit.
    $bytes = New-Object byte[] 18
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Password = [Convert]::ToBase64String($bytes)
}

Say "Creating self-signed code-signing certificate"
Info "  subject: $Subject"

# 2.5.29.37 = Extended Key Usage; 1.3.6.1.5.5.7.3.3 = Code Signing.
# The empty 2.5.29.19 (Basic Constraints) marks it an end-entity cert.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($Years) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')

Ok "thumbprint: $($cert.Thumbprint)"
Ok "expires:    $($cert.NotAfter)"

$pfxPath = Join-Path $OutDir 'meshharbor-dev.pfx'
$cerPath = Join-Path $OutDir 'meshharbor-dev.cer'
$pwSecure = ConvertTo-SecureString -String $Password -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwSecure | Out-Null
Export-Certificate    -Cert $cert -FilePath $cerPath | Out-Null
Ok "pfx: $pfxPath   (PRIVATE KEY -- gitignored, never commit)"
Ok "cer: $cerPath   (public, safe to distribute for GPO/Intune trust)"

$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath))
$b64Path = Join-Path $OutDir 'meshharbor-dev.pfx.base64'
Set-Content -Path $b64Path -Value $b64 -Encoding ascii
$pwPath = Join-Path $OutDir 'meshharbor-dev.password.txt'
Set-Content -Path $pwPath -Value $Password -Encoding ascii

Write-Host ''
if ($PushSecrets) {
    Say "Setting repository secrets on $Repo"
    Require-Command 'gh' 'Install: https://cli.github.com/' | Out-Null
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $b64 | & gh secret set WIN_TEST_PFX_BASE64 --repo $Repo 2>&1 | Out-Null
    $c1 = $LASTEXITCODE
    $Password | & gh secret set WIN_TEST_PFX_PASSWORD --repo $Repo 2>&1 | Out-Null
    $c2 = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($c1 -eq 0) { Ok 'WIN_TEST_PFX_BASE64 set' }   else { Warn 'failed to set WIN_TEST_PFX_BASE64' }
    if ($c2 -eq 0) { Ok 'WIN_TEST_PFX_PASSWORD set' } else { Warn 'failed to set WIN_TEST_PFX_PASSWORD' }
} else {
    Say 'To let CI rehearse with this cert:'
    Info "  gh secret set WIN_TEST_PFX_BASE64   --repo $Repo < `"$b64Path`""
    Info "  gh secret set WIN_TEST_PFX_PASSWORD --repo $Repo < `"$pwPath`""
    Info '  (or re-run this script with -PushSecrets)'
}

Write-Host ''
Say 'Rehearse the pipeline with it (no tag, no publish, no Azure):'
Info "  gh workflow run release-agent.yml  --repo $Repo -f publish_release=false -f signing_mode=local -f require_signing=true"
Info "  gh workflow run release-setup.yml  --repo $Repo -f publish_release=false -f signing_mode=local"
Info "  gh workflow run release-tunnel.yml --repo $Repo -f publish_release=false -f signing_mode=local"
Write-Host ''
Info 'Negative test -- the gate must FAIL, not warn:'
Info "  gh workflow run release-agent.yml  --repo $Repo -f publish_release=false -f signing_mode=off -f require_signing=true"
Write-Host ''
Info 'To trust it on pilot machines: pwsh scripts/signing/51-trust-dev-cert.ps1'
Write-Host ''
Warn 'Artifacts signed with this certificate MUST NOT be published. It exists to'
Warn 'prove the YAML, not to vouch for anything.'
