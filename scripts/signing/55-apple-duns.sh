#!/usr/bin/env bash
# 55-apple-duns.sh -- get the D-U-N-S number Apple's ORGANIZATION enrolment
# requires, for G ROX LTD.
#
#   ./scripts/signing/55-apple-duns.sh           # print the guided flow + field sheet
#   ./scripts/signing/55-apple-duns.sh check     # things to verify before/after
#
# There is NO public API for any of this -- both the lookup and the request
# are web forms behind an Apple ID sign-in. This script exists to make the
# manual pass a 5-minute copy-paste job instead of a research project, and
# to encode the one insight that usually saves the whole 1-2 week wait:
#
#   LOOK UP FIRST. Dun & Bradstreet auto-creates D-U-N-S records from
#   public business registries. A Bulgarian company that has been in the
#   commercial register since 2018 (UIC 205174895) very likely ALREADY has
#   one -- in which case there is nothing to request, only a number to
#   retrieve, and Apple e-mails it within minutes.
#
# Flow (all via Apple's own channel -- it is free and faster than going to
# dnb.com, and the result lands directly in Apple's enrolment system):
#
#   1. https://developer.apple.com/enroll/duns-lookup/
#      Sign in with the Apple ID that will own the developer account.
#   2. Fill the lookup form with the field sheet below. EXACT legal name --
#      the same character-for-character rule as the Azure validation.
#   3. Outcome A (most likely): "Your organization was found" -- Apple
#      e-mails the D-U-N-S number to the Apple ID address. DONE.
#   4. Outcome B: not found -- the SAME form offers "submit your
#      information to Dun & Bradstreet". Do that (free). D&B assigns a new
#      number in ~5 business days (up to 14); they may phone to verify.
#   5. Either way, once the number arrives: enrol at
#      https://developer.apple.com/programs/enroll/ as an ORGANIZATION
#      (99 USD/yr), then run: ./scripts/signing/60-apple-setup.sh csr
#
# Gotchas encoded from the field:
#   * Enrol as ORGANIZATION, not Individual -- an individual enrolment
#     stamps a personal name on every Developer ID signature, defeating the
#     G ROX LTD identity that Windows publishing already carries.
#   * The D&B record's legal name must match the register: "G ROX LTD".
#     If D&B holds a stale/transliterated name (e.g. "G ROX OOD" or a
#     Cyrillic rendering), request a correction in the same flow BEFORE
#     enrolling -- Apple compares the two and a mismatch stalls enrolment
#     in "additional information required" for weeks.
#   * The person enrolling must have LEGAL AUTHORITY to bind the company.
#     Goran Jovanov is 100% owner + CEO, so select "I am the owner/founder"
#     when asked.
#   * Apple's verification team may call the company phone number on file.
#     Use a number that is actually answered: +359 87 711 8883.

set -euo pipefail

say()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }

field_sheet() {
    say 'Field sheet for the D-U-N-S lookup / request (copy-paste)'
    info ''
    info 'Legal entity name:   G ROX LTD'
    info 'Headquarters:        Plovdivska 110'
    info 'City:                Pazardzhik'
    info 'ZIP:                 4400'
    info 'Country:             Bulgaria'
    info 'Phone:               +359877118883'
    info 'Registration (UIC):  205174895        (Bulgarian commercial register)'
    info 'VAT:                 BG205174895'
    info 'Website:             https://meshharbor.itachi.fans'
    info 'Your name:           Goran Jovanov    (owner & CEO, 100%)'
    info ''
}

case "${1:-flow}" in
    check)
        say 'Before the lookup'
        info '* Decide which Apple ID owns the developer account (it receives the'
        info '  D-U-N-S e-mail and, later, the enrolment). A company-domain address'
        info '  (e.g. goran.jovanov@meshharbor.itachi.fans) looks better in org verification'
        info '  than a personal gmail.'
        info '* Have the UIC handy for the D&B verification call: 205174895.'
        echo
        say 'After the number arrives'
        info '* Save it: it goes into the enrolment form, nowhere else in this repo.'
        info '* Enrol as ORGANIZATION at https://developer.apple.com/programs/enroll/'
        info '* Then: ./scripts/signing/60-apple-setup.sh csr'
        ;;
    flow|*)
        say 'Step 1 -- LOOK UP FIRST (the number probably already exists)'
        info 'Open:  https://developer.apple.com/enroll/duns-lookup/'
        info 'Sign in with the Apple ID that will own the developer account.'
        echo
        field_sheet
        say 'Step 2 -- outcomes'
        info 'FOUND      -> D-U-N-S arrives by e-mail in minutes. Done.'
        info 'NOT FOUND  -> the same form submits a free request to D&B'
        info '              (~5 business days, up to 14; expect a phone check).'
        echo
        say 'Step 3 -- enrol (needs the number)'
        info 'https://developer.apple.com/programs/enroll/  -> Organization, 99 USD/yr'
        info 'Then: ./scripts/signing/60-apple-setup.sh csr'
        ;;
esac
