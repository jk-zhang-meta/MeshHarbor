# 10-azure-provision.ps1 -- create the Azure Artifact Signing account and
# grant the operator the rights needed to submit an identity validation.
#
# This is the LONG POLE: identity validation is portal-only (Microsoft
# does not expose it via CLI) and takes 1 to 20 business days. Run this
# early; everything in .github/ can be built and rehearsed with the free
# self-signed cert (50-selfsigned-dev-cert.ps1) while it processes.
#
#   pwsh scripts/signing/00-preflight.ps1 -Country AT
#   pwsh scripts/signing/10-azure-provision.ps1 -OrganizationName "Example GmbH" `
#        -BusinessIdentifier "FN 123456a" -Street "Mustergasse 1" -City "Wien" `
#        -PostalCode "1010" -CountryCode AT -PrimaryEmail "codesign@meshharbor.itachi.fans" `
#        -SecondaryEmail "admin@meshharbor.itachi.fans"
#
# Idempotent: re-running against an existing resource group / account is a
# no-op plus a re-print of the portal field sheet.

[CmdletBinding()]
param(
    [string]$Sku = 'Basic',

    # Everything below is only used to render the portal field sheet at the
    # end. Nothing is transmitted -- identity validation is a portal form.
    #
    # Pre-filled with G ROX LTD's registered details. The Organization Name
    # MUST match the Bulgarian commercial register character for character;
    # verify it in the register before submitting, because a correction later
    # requires a brand-new validation request and invalidates any certificate
    # profile already bound to the old one.
    [string]$OrganizationName   = 'G ROX LTD',
    # Bulgarian UIC/EIK -- the VAT number BG205174895 without the country
    # prefix. This is the public business-register identifier the validator
    # looks the company up by.
    [string]$BusinessIdentifier = '205174895',
    [string]$WebsiteUrl         = 'https://meshharbor.itachi.fans',
    [string]$Street             = 'Plovdivska 110',
    [string]$City               = 'Pazardzhik',
    [string]$StateProvince      = '',
    [string]$PostalCode         = '4400',
    [string]$CountryCode        = 'BG',
    # MUST be on a domain the entity owns -- a gmail.com address is rejected.
    # Both addresses must accept external links; verification links expire in
    # 7 days.
    [string]$PrimaryEmail       = '',
    [string]$SecondaryEmail     = ''
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
$subscriptionId = Get-StateValue $state 'subscriptionId'
$rg             = Get-StateValue $state 'resourceGroup'
$account        = Get-StateValue $state 'accountName'
$location       = Get-StateValue $state 'location'
$endpoint       = Get-StateValue $state 'endpoint'

if (-not $subscriptionId -or -not $rg -or -not $account -or -not $location) {
    Fail 'missing state. Run 00-preflight.ps1 first.'
}
if (-not $CountryCode) { $CountryCode = Get-StateValue $state 'country' '' }

# Account-name constraints are enforced server-side with an unhelpful
# message; check locally so a typo costs a second, not a round trip.
if ($account -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') {
    Fail "account name '$account' is invalid: 3-24 chars, start with a letter, end alphanumeric."
}
if ($account -match '--')            { Fail "account name '$account' must not contain consecutive hyphens." }
if ($account -match '^(?i)one')      { Fail "account name '$account' must not start with 'one' (rejected by ARM)." }

Say "Subscription $subscriptionId"
Invoke-Az account set --subscription $subscriptionId | Out-Null

# ------------------------------------------------------- resource provider
Say 'Registering resource provider Microsoft.CodeSigning'
$rp = Invoke-AzJson provider show --namespace Microsoft.CodeSigning
if ($rp.registrationState -ne 'Registered') {
    Invoke-Az provider register --namespace Microsoft.CodeSigning | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 5
        $rp = Invoke-AzJson provider show --namespace Microsoft.CodeSigning
        if ($rp.registrationState -eq 'Registered') { break }
        Info "  registrationState=$($rp.registrationState) ..."
    }
}
if ($rp.registrationState -ne 'Registered') { Fail "provider stuck at $($rp.registrationState)" }
Ok 'Microsoft.CodeSigning registered'

# ------------------------------------------------------------- extension
Say 'Installing the artifact-signing CLI extension'
$ext = Invoke-AzJson extension list
if ($ext | Where-Object { $_.name -eq 'artifact-signing' }) {
    Invoke-Az extension update --name artifact-signing | Out-Null
    Ok 'artifact-signing extension up to date'
} else {
    Invoke-Az extension add --name artifact-signing | Out-Null
    Ok 'artifact-signing extension installed'
}

# --------------------------------------------------------- resource group
Say "Resource group $rg ($location)"
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$exists = (& az group exists --name $rg 2>$null)
$ErrorActionPreference = $prev
if ($exists -match 'true') {
    Ok "$rg already exists"
} else {
    Invoke-Az group create --name $rg --location $location | Out-Null
    Ok "$rg created"
}

# --------------------------------------------------------------- account
Say "Artifact Signing account $account (sku $Sku)"
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$acctRaw = & az artifact-signing show -g $rg -n $account -o json 2>$null
$acctCode = $LASTEXITCODE
$ErrorActionPreference = $prev
if ($acctCode -eq 0 -and $acctRaw) {
    Ok "$account already exists"
} else {
    Invoke-Az artifact-signing create -n $account -l $location -g $rg --sku $Sku | Out-Null
    Ok "$account created"
}
$acct = Invoke-AzJson artifact-signing show -g $rg -n $account
$accountId = $acct.id
Info "  resource id: $accountId"

# ------------------------------------------------------------------ roles
# 'Artifact Signing Identity Verifier' is what un-greys the "New identity"
# button in the portal, and it additionally requires Reader at SUBSCRIPTION
# scope -- a documented prerequisite that is easy to miss and produces a
# silently disabled button rather than an error.
Say 'Role assignments for the operator'
$me = Invoke-AzJson ad signed-in-user show
$myId = $me.id
Info "  signed-in user object id: $myId"

function Ensure-Role([string]$RoleName, [string]$Scope) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $have = & az role assignment list --assignee $myId --role $RoleName --scope $Scope -o json 2>$null
    $ErrorActionPreference = $prev
    if ($LASTEXITCODE -eq 0 -and $have -and ($have | ConvertFrom-Json).Count -gt 0) {
        Ok "$RoleName already assigned"
        return
    }
    Invoke-Az role assignment create --assignee $myId --role $RoleName --scope $Scope | Out-Null
    Ok "$RoleName assigned"
}

Ensure-Role 'Reader' "/subscriptions/$subscriptionId"
Ensure-Role 'Artifact Signing Identity Verifier' $accountId

$state = Set-StateValue $state 'accountResourceId' $accountId
Save-State $state

# ------------------------------------------------------ portal field sheet
$portal = "https://portal.azure.com/#@/resource$accountId/identityValidations"

Write-Host ''
Say 'MANUAL STEP -- identity validation is portal-only'
Info "Open: $portal"
Info ''
Info 'Identity validations -> select Organization -> New Identity -> Public.'
Info 'Fill the form with EXACTLY these values:'
Info ''

function Field([string]$label, [string]$value) {
    if ($value) { Write-Host ("    {0,-22} {1}" -f $label, $value) }
    else        { Write-Host ("    {0,-22} <FILL IN>" -f $label) -ForegroundColor Yellow }
}
Field 'Organization Name'   $OrganizationName
Field 'Website url'         $WebsiteUrl
Field 'Business Identifier' $BusinessIdentifier
Field 'Primary Email'       $PrimaryEmail
Field 'Secondary Email'     $SecondaryEmail
Field 'Street'              $Street
Field 'City'                $City
Field 'State/Province'      $StateProvince
Field 'Postal code'         $PostalCode
Field 'Country/Region'      $CountryCode
Field 'First / Last name'   '<the individual representing the org, as printed on their photo ID>'

Info ''
Warn 'Organization Name must match the public business register CHARACTER FOR CHARACTER.'
Warn 'There is no edit: correcting a field later requires a brand-new validation request,'
Warn 'which invalidates certificate profiles already bound to the old one.'
Info ''
Info 'Click "Certificate subject preview" before submitting and copy what it shows --'
Info 'that string becomes the Windows "Verified publisher" text, and every Manufacturer /'
Info 'copyright field in the repo has to be swept to match it.'
Info ''
Info 'Processing takes 1 to 20 business days. Watch it with:'
Info '    pwsh scripts/signing/15-azure-identity-status.ps1   (portal deep-link + next steps)'
