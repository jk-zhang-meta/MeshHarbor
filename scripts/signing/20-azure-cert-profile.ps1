# 20-azure-cert-profile.ps1 -- create the Public Trust certificate profile
# once identity validation has reached Completed.
#
#   pwsh scripts/signing/20-azure-cert-profile.ps1
#   pwsh scripts/signing/20-azure-cert-profile.ps1 -ProfileType PublicTrustTest
#
# PublicTrustTest issues from a TEST root that is NOT in the Windows trust
# store. It is useful for proving the CI plumbing end to end without
# consuming Public Trust quota, but such artifacts must never be published:
# they verify only on a machine that has explicitly trusted the test root.

[CmdletBinding()]
param(
    [ValidateSet('PublicTrust', 'PublicTrustTest')]
    [string]$ProfileType = 'PublicTrust',
    [string]$ProfileName = '',
    [switch]$IncludeStreetAddress,
    [switch]$IncludePostalCode
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
$subscriptionId = Get-StateValue $state 'subscriptionId'
$rg             = Get-StateValue $state 'resourceGroup'
$account        = Get-StateValue $state 'accountName'
$identityId     = Get-StateValue $state 'identityValidationId'
if (-not $ProfileName) { $ProfileName = Get-StateValue $state 'profileName' 'meshharbor-public-trust' }

if (-not $subscriptionId -or -not $rg -or -not $account) {
    Fail 'missing state. Run 00-preflight.ps1 and 10-azure-provision.ps1 first.'
}
if (-not $identityId) {
    Fail ('no completed identity validation recorded. Run: ' +
          'pwsh scripts/signing/15-azure-identity-status.ps1 -SetId <guid from the portal blade>')
}

# Profile-name constraints, checked locally (server message is unhelpful).
if ($ProfileName -notmatch '^[A-Za-z][A-Za-z0-9-]{3,98}[A-Za-z0-9]$') {
    Fail "profile name '$ProfileName' is invalid: 5-100 chars, start with a letter, end alphanumeric."
}
if ($ProfileName -match '--') { Fail "profile name '$ProfileName' must not contain consecutive hyphens." }

Invoke-Az account set --subscription $subscriptionId | Out-Null

Say "Certificate profile $ProfileName ($ProfileType)"
Info "  identity validation: $identityId"

$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$existingRaw = & az artifact-signing certificate-profile show -g $rg --account-name $account -n $ProfileName -o json 2>$null
$existingCode = $LASTEXITCODE
$ErrorActionPreference = $prev

if ($existingCode -eq 0 -and $existingRaw) {
    Ok "$ProfileName already exists"
    $profile = $existingRaw | ConvertFrom-Json
} else {
    $args = @(
        'artifact-signing', 'certificate-profile', 'create',
        '-g', $rg, '--account-name', $account, '-n', $ProfileName,
        '--profile-type', $ProfileType,
        '--identity-validation-id', $identityId
    )
    if ($IncludeStreetAddress) { $args += @('--include-street', 'true') }
    if ($IncludePostalCode)    { $args += @('--include-postal-code', 'true') }
    Invoke-Az @args | Out-Null
    Ok "$ProfileName created"
    $profile = Invoke-AzJson artifact-signing certificate-profile show -g $rg --account-name $account -n $ProfileName
}

$profileId = "/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.CodeSigning/codeSigningAccounts/$account/certificateProfiles/$ProfileName"
Info "  resource id: $profileId"

$subject = $null
foreach ($p in @('subjectName', 'subject', 'commonName')) {
    if ($profile -and ($profile.PSObject.Properties.Name -contains $p) -and $profile.$p) { $subject = $profile.$p; break }
}
if (-not $subject -and $profile.properties) {
    foreach ($p in @('subjectName', 'subject', 'commonName')) {
        if (($profile.properties.PSObject.Properties.Name -contains $p) -and $profile.properties.$p) {
            $subject = $profile.properties.$p; break
        }
    }
}

$state = Set-StateValue $state 'profileName'        $ProfileName
$state = Set-StateValue $state 'profileType'        $ProfileType
$state = Set-StateValue $state 'profileResourceId'  $profileId
if ($subject) { $state = Set-StateValue $state 'certificateSubject' $subject }
Save-State $state

Write-Host ''
if ($subject) {
    Write-Host '    Certificate subject:' -ForegroundColor Cyan
    Write-Host "      $subject" -ForegroundColor Cyan
    Write-Host ''
    Info 'Set this as expect-subject-contains in the sign-windows action so a'
    Info 'profile swap can never silently change the publisher, and sweep the'
    Info 'Manufacturer / copyright fields to match (see 15-azure-identity-status.ps1).'
}
if ($ProfileType -eq 'PublicTrustTest') {
    Write-Host ''
    Warn 'PublicTrustTest certificates chain to a TEST root that is NOT trusted by'
    Warn 'Windows. Artifacts signed with this profile MUST NOT be published.'
}

Info ''
Info 'Next: pwsh scripts/signing/30-github-oidc.ps1'
