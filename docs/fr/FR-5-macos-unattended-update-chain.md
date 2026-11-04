# FR-5: macOS unattended update chain — the update half, pinned-GPG artifact trust, and a stable code-signing identity (retrospective)

**Status:** SHIPPED and field-closed 2026-08-26 at agent rc.482. Tracking issue: `FR-5` (#774)
in gjovanov/roomler-ai/issues. Retrospective FR — the arc completed before this document;
every claim below carries its field receipt.

## Goal

A macOS device (default install = the per-user LaunchAgent alone) must take agent updates
**unattended and safely**: no human hands per update, no offline gap, no loss of the
TCC permissions the user granted, and no installing bytes that cannot be attributed to
this project's release key. Before this arc, macOS had none of the four: the default
install could not self-update at all, the two-half install went offline on every pushed
update (five field occurrences), `.deb`/`.pkg` installed on transport trust alone, and
every update wiped Screen Recording + Accessibility.

## The four problems and their fixes

### 1. Agents installed their own replacement and died doing it — **the update half** (#714)

`installer -target /` needs root; the per-user half isn't. Worse, the exit-to-update dance
(spawn installer, exit, hope launchd restarts you) raced launchd job replacement.
Fix: a third launchd unit, **`fans.itachi.meshharbor.update`**, installed by the pkg BY DEFAULT
<!-- RETIRED-NAME-ANCHOR(2): the real macOS daemon config dir, read by the
     shipped .pkg postinstall. FR-21 D5. -->
(opt-out marker `/etc/roomler-agent/disable-auto-update`, absence-removes): a root,
single-shot helper (`roomlerd update-helper`, hidden subcommand) that owns
check → download → verify → `installer -pkg … -target /`. Agents only touch the wake file
`/private/var/tmp/roomler-update-check` — **whose content is deliberately ignored** (a pin
honoured from a sticky world-writable path would hand any local user a
root-installs-a-genuine-but-old-release downgrade primitive). Wake sources: RunAtLoad +
StartInterval 6 h + WatchPaths; `ThrottleInterval` 60 s; install-storm cooldown shared
with the old updater via the root marker.

- **Receipts**: uid-501 touch → root helper verdict in **738 ms**; push → installed →
  both halves back in **~40 s** (first proof) and **16 s** (second); five fully
  autonomous installs by rc.482 (~4 s each once cached).

### 2. The per-user half died at every install — **the bootout drain race** (#718) and **the launchd failed-init latch** (#742)

`launchctl bootout` returns while the old agent is still draining its WebRTC teardown;
an immediate `bootstrap` gets `Bootstrap failed: 5: Input/output error` — caught twice in
`/var/log/install.log` (rc.472, rc.474 cycles). Fix: `replace_launchd_service()` in
postinstall — bootout → poll the domain until the service is GONE (≤15 s) → bootstrap
with retries; applied to agent + tray + daemon (whose old form was a *bare* bootstrap
under `set -e`).

Separately, launchd **latches "failed init"** on a job whose spawn ever failed (field: a
trigger raced a pkg's atomic bundle shove while the executable was transiently absent);
every later wake is then a synthetic `exit(78) ran for 8ms` with *nothing in the job's own
log*, while by-hand execution works — that contrast is the diagnostic tell. Fix (#742):
postinstall re-cycles the update unit when IDLE (clears latches, applies refreshed
plists), hands-off only when the job is RUNNING (it is this very install's ancestor).

- **Receipts**: rc.475's postinstall line "installed and started for gjovanov (uid=501)"
  where rc.474's logged the EIO; the healed unit woke a trigger-touch at exactly the 60 s
  throttle boundary and consumed it.

### 3. `.deb`/`.pkg` installed on transport trust — **pinned-GPG verification** (#724)

The manifest's SHA256 arrives from the same origin as the URL — a transport check, not a
tamper anchor. Fix: the release signing subkey's ed25519 point (fpr
`5DB8221F546288DE780C10D3A2C53E5FE6FA485A`) is **compiled into the binary**
(`pgp_verify.rs`, in `crates/tunnel-core/src` since FR-97 P6b); `download_asset` on Linux/macOS fetches
`<asset-url>.asc` and refuses fail-closed. Deliberately not an OpenPGP implementation:
~150 lines of RFC 4880 framing for exactly the shape CI emits (one v4 packet, class 0x00,
EdDSA, SHA-256/512), ring doing the ed25519 (already in the graph — zero new deps).
`pinned_key_matches_committed_pubkey` re-derives the constant from
`scripts/signing/gpg/roomler-release-pubkey.asc` every test run, so pin and file cannot
drift. Key rotation requires a release; the overlap recipe is in the module docs.

- **Receipts**: the real rc.475 `.pkg` (20.2 MB) verifies, one flipped mid-file byte is
  refused (`--ignored real_published_asc`); LIVE in the field twice —
  `installer .asc verified against the pinned release signing key` for the rc.481 and
  rc.482 downloads before each unattended install.

### 4. Every update wiped the TCC grants — **a stable self-signed code-signing identity** (#729, #737, #740)

TCC keys grants on the code-signing **designated requirement**. Ad-hoc signing
(`codesign --sign -`) pins a per-build cdhash — a new identity every build — so every
update re-blinded the Mac (deterministic across rc.475/476). Fix: ONE self-signed cert
(RSA-2048, `CN=Roomler Self-Signed Code Signing`, valid to 2036), minted once, held in
repo secrets (`MACOS_SELFSIGN_P12`/`_PASSWORD`, offline backup with the operator),
imported into a temp keychain per release run; all three codesign sites use it with
`--timestamp=none`; an Authority assert guards against silently shipping ad-hoc. Not
notarization — Gatekeeper is unchanged (installs ride `curl | sh`, no quarantine xattr);
purely identity stability. Superseded file-by-file by Developer ID when Apple's D-U-N-S
clears.

The **four-trap ladder** to make self-signed signing work in CI, each field-hit once:
1. OpenSSL 3's default p12 (PBKDF2-SHA256 MAC) is rejected by macOS `security import` —
   export with `-legacy`.
2. `gh secret set NAME < file` stores the trailing newline — `tr -d '\r\n'` first.
3. An imported self-signed cert has **no trust settings**, and both
   `find-identity -v -p codesigning` and codesign require codesigning trust —
   `sudo security add-trusted-cert -d -r trustRoot -p codeSign -k /Library/Keychains/System.keychain <cert>`.
4. `Authority=` lines only print at `codesign -d --verbose=2`; a `-dv` grep fails on a
   perfectly-signed bundle.

- **Receipts**: rc.479/480/482 all carry the byte-identical DR
  `identifier "fans.itachi.meshharbor.agent" and certificate root = H"b2a06501a54c27be3fea609ce04c1e55cd0a4f52"` —
  **the DR-equivalence check (`codesign -d -r-` old vs new) proves grant survival with no
  grant present**. Operator-confirmed on rc.482: *"screen worked directly"*, no re-grant.
  Observed TCC asymmetry, recorded not modeled: Screen Recording survived even the
  ad-hoc→cert flip; Accessibility stayed revoked (`has_input_permission:false`) — grant it
  once only if remote INPUT on the Mac matters.

## Acceptance criteria (all field-verified)

- [x] A pushed update installs unattended with both halves back online, no hands
      (five consecutive autonomous installs; push→back ≤40 s).
- [x] The default (per-user-only) install flavour self-updates (the helper needs no
      enrollment — public release feed).
- [x] A `.pkg`/`.deb` that does not verify against the pinned release key is refused,
      discarded, and the current version kept (unit + real-artifact + live proofs).
- [x] TCC grants survive updates (DR equality across rc.479→482 + operator confirmation).
- [x] A wedged updater self-heals at the next install (#742 idle re-cycle).
- [x] Opt-out works and round-trips (`disable-auto-update` marker; CI smoke asserts both
      polarities).

## Out of scope / follow-ups

- Apple Developer ID + notarization — blocked externally on D-U-N-S; replaces the
  self-signed identity file-by-file when it lands.
- The release manifest itself is unsigned (version+url+hash not attested as a unit).
- The tunnel CLI's separate `self-update` does not share `download_asset` and is not yet
  pinned.
- Windows/Linux keep their existing paths (Authenticode + name check; dpkg) — the update
  half is macOS-only by design.

## Related

CLAUDE.md "Code signing" + the auto-updater Known-Issues entry; PRs #714 #718 #720 #724
#729 #737 #740 #742; releases agent-v0.3.0-rc.473…482 (rc.477/478 are dead tags — the
four-trap ladder consumed them; no releases published under them).
