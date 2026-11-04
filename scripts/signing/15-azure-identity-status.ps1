# 15-azure-identity-status.ps1 -- the bridge between the portal-only identity
# validation and the scripted rest of the pipeline.
#
# Identity validations are NOT an ARM resource ("ResourceTypeRegistrationNot-
# Found" on every api-version; verified 2026-08-18) and the artifact-signing
# CLI extension exposes only certificate-profile + check-name-availability.
# Microsoft's docs say it outright: identity validation can be completed ONLY
# in the Azure portal. There is nothing to poll from a terminal -- the portal
# blade and its e-mail notifications are the only status surface.
#
# So this script does the two things that ARE possible:
#
#   (default)        print where to look + what each status means, and show
#                    what is already recorded in the shared state
#   -SetId <guid>    record the "Identity validation Id" copied from the
#                    portal blade (plus -Subject) into the state file, which
#                    is what unblocks 20-azure-cert-profile.ps1
#
#   pwsh scripts/signing/15-azure-identity-status.ps1
#   pwsh scripts/signing/15-azure-identity-status.ps1 -SetId 12345678-... `
#        -Subject 'CN=G ROX LTD, O=G ROX LTD, L=Pazardzhik, C=BG'

[CmdletBinding()]
param(
    # The "Identity validation Id" shown on the portal blade once you open
    # the completed validation entry.
    [string]$SetId = '',
    # The "Certificate subject preview" / issued subject from the same blade.
    [string]$Subject = ''
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
$subscriptionId = Get-StateValue $state 'subscriptionId'
$rg             = Get-StateValue $state 'resourceGroup'
$account        = Get-StateValue $state 'accountName'
if (-not $subscriptionId -or -not $rg -or -not $account) {
    Fail 'missing state. Run 00-preflight.ps1 and 10-azure-provision.ps1 first.'
}

$blade = "https://portal.azure.com/#@/resource/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.CodeSigning/codeSigningAccounts/$account/identityValidations"

# ------------------------------------------------------------------ -SetId
if ($SetId) {
    if ($SetId -notmatch '^[0-9a-fA-F-]{32,36}$') {
        Fail "'$SetId' does not look like an identity-validation GUID."
    }
    $state = Set-StateValue $state 'identityValidationId' $SetId
    if ($Subject) { $state = Set-StateValue $state 'certificateSubject' $Subject }
    Save-State $state
    Ok "identity validation id recorded: $SetId"
    if ($Subject) {
        Ok "certificate subject recorded: $Subject"
        Write-Host ''
        Warn 'Sweep check -- the Windows "Verified publisher" string must agree with:'
        Info '  agents/meshharbord/wix/main.wxs + wix-perMachine/main.wxs (Manufacturer)'
        Info '  agents/meshharbord/build.rs + agents/meshharbor-cli/build.rs (CompanyName)'
        Info '  both tauri.conf.json (bundle.publisher) + both [package.metadata.deb]'
    } else {
        Info 'no -Subject given -- 20-azure-cert-profile.ps1 will try to read it after profile creation.'
    }
    Info ''
    Info 'Next: pwsh scripts/signing/20-azure-cert-profile.ps1'
    exit 0
}

# ----------------------------------------------------------------- status
Say "Identity validation for $account"
Info ''
Info 'Status lives ONLY in the portal (there is no ARM resource and no CLI'
Info 'command for it -- creation and progress are portal + e-mail only):'
Info ''
Info "  $blade"
Info ''
Info 'What the statuses mean:'
Info '  In Progress      queued with the validation team; nothing to do'
Info '  Action Required  OPEN THE ENTRY -- usually the Verified-ID mobile flow'
Info '                   or a document upload (only 3 upload attempts; docs'
Info '                   must be <12 months old)'
Info '  Completed        copy the "Identity validation Id" from the blade, then:'
Info '                     pwsh scripts/signing/15-azure-identity-status.ps1 -SetId <guid> -Subject "<subject>"'
Info '  Failed           a mismatch with the business register is the usual'
Info '                   cause; a NEW request must be created (no edits)'
Info ''
Info 'Microsoft also e-mails every status change to the primary address on'
Info 'the request. Processing takes 1 to 20 business days.'

$haveId = Get-StateValue $state 'identityValidationId' ''
$haveSubject = Get-StateValue $state 'certificateSubject' ''
Write-Host ''
if ($haveId) {
    Ok "state already holds identityValidationId: $haveId"
    if ($haveSubject) { Ok "state already holds subject: $haveSubject" }
    Info 'Next: pwsh scripts/signing/20-azure-cert-profile.ps1'
} else {
    Info 'state holds no identityValidationId yet.'
}
