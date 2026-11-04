# 51-trust-dev-cert.ps1 -- trust the self-signed dev certificate on THIS
# machine, and print the GPO / Intune recipes for doing it across a fleet.
#
#   pwsh scripts/signing/51-trust-dev-cert.ps1                    # install
#   pwsh scripts/signing/51-trust-dev-cert.ps1 -Remove            # uninstall
#   pwsh scripts/signing/51-trust-dev-cert.ps1 -PrintFleetRecipe  # no changes
#
# Why both stores:
#   Root             -- makes the chain valid at all (self-signed = own root)
#   TrustedPublisher -- what actually suppresses the "unknown publisher"
#                       prompts and what an AppLocker/WDAC publisher rule
#                       matches against
#
# Scope note: this unblocks a corporate PILOT today, months before a public
# cert changes anything for machines outside the managed fleet. It is a
# stop-gap. Remove both entries when the pilot ends -- a lingering
# self-signed root on a managed fleet is a real risk, because anyone holding
# that .pfx can sign anything and have it trusted.

[CmdletBinding()]
param(
    [string]$CerPath = '',
    [switch]$Remove,
    [switch]$PrintFleetRecipe
)

. "$PSScriptRoot\_common.ps1"

if (-not $CerPath) { $CerPath = Join-Path $PSScriptRoot 'dev-cert\meshharbor-dev.cer' }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$stores = @('Root', 'TrustedPublisher')

if (-not $PrintFleetRecipe) {
    if (-not (Test-Path $CerPath)) {
        Fail "certificate not found at $CerPath. Run 50-selfsigned-dev-cert.ps1 first, or pass -CerPath."
    }
    if (-not (Test-Elevated)) {
        Fail 'LocalMachine store changes need an ELEVATED PowerShell (Terminal (Admin)).'
    }

    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $CerPath
    $thumb = $cert.Thumbprint
    Info "  subject:    $($cert.Subject)"
    Info "  thumbprint: $thumb"

    foreach ($s in $stores) {
        $path = "Cert:\LocalMachine\$s"
        if ($Remove) {
            $found = Get-ChildItem $path | Where-Object { $_.Thumbprint -eq $thumb }
            if ($found) { $found | Remove-Item -Force; Ok "removed from LocalMachine\$s" }
            else        { Info "  not present in LocalMachine\$s" }
        } else {
            Import-Certificate -FilePath $CerPath -CertStoreLocation $path | Out-Null
            Ok "imported into LocalMachine\$s"
        }
    }

    Write-Host ''
    if ($Remove) { Ok 'dev certificate untrusted on this machine.' }
    else {
        Ok 'dev certificate trusted on this machine.'
        Info 'Verify: Get-AuthenticodeSignature <signed.exe>  ->  Status should be Valid'
    }
    Write-Host ''
}

# ------------------------------------------------------------ fleet recipe
$thumbHint = 'THUMBPRINT'
if (Test-Path $CerPath) {
    $thumbHint = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $CerPath).Thumbprint
}

Say 'Fleet deployment -- Group Policy'
Info '  Group Policy Management -> edit a GPO linked to the pilot OU ->'
Info '  Computer Configuration -> Policies -> Windows Settings -> Security Settings'
Info '  -> Public Key Policies, then import meshharbor-dev.cer into BOTH:'
Info '       * Trusted Root Certification Authorities'
Info '       * Trusted Publishers'
Info '  Both are required: Root makes the chain valid, TrustedPublisher is what'
Info '  suppresses the prompts and what publisher rules match.'
Write-Host ''

Say 'Fleet deployment -- Intune'
Info '  Intune has no built-in template for TrustedPublisher, so it takes two profiles:'
Info ''
Info '  1. Devices -> Configuration -> Create -> Windows 10 and later ->'
Info '     Templates -> Trusted certificate'
Info '       upload meshharbor-dev.cer'
Info '       Destination store: Computer certificate store - Root'
Info ''
Info '  2. Devices -> Configuration -> Create -> Windows 10 and later -> Templates -> Custom'
Info "       OMA-URI: ./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/$thumbHint/EncodedCertificate"
Info '       Data type: String'
Info '       Value:     the base64 of meshharbor-dev.cer (below)'
Write-Host ''
Info '  Equivalent if you deploy a platform script instead of a profile:'
Info '       Import-Certificate -FilePath meshharbor-dev.cer -CertStoreLocation Cert:\LocalMachine\Root'
Info '       Import-Certificate -FilePath meshharbor-dev.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher'
Write-Host ''

if (Test-Path $CerPath) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($CerPath))
    $b64Path = Join-Path (Split-Path -Parent $CerPath) 'meshharbor-dev.cer.base64'
    Set-Content -Path $b64Path -Value $b64 -Encoding ascii
    Ok "base64 for the OMA-URI value written to $b64Path"
}

Write-Host ''
Warn 'Remove both entries when the pilot ends:'
Info '  pwsh scripts/signing/51-trust-dev-cert.ps1 -Remove     (per machine)'
Info '  ...and delete the GPO / Intune profiles.'
