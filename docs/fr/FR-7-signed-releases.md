# FR-7: Signed releases — Windows Authenticode (Azure), Linux GPG + provenance, macOS identity

**Status: SHIPPED + field-verified** (retroactive FR per the CLAUDE.md standing rule —
the program ran 2026-08-15 → 2026-08-26; this spec records what was required, what was
built, and how each requirement was proven. Tracking issue: jk-zhang-meta/MeshHarbor#778. Renumbered FR-3→FR-7 per the lower-issue-id tie-break after the day-one mint races.)

## Goal

Every published MeshHarbor artifact — MSIs and the EXEs inside them, the macOS `.pkg`
and wizard, the tunnel CLI, the `.deb`s — carries a verifiable publisher identity,
and the release pipeline makes an unsigned release **impossible** rather than
merely unlikely. Publisher of record: **G ROX LTD** (BG, UIC 205174895; the
Bulgarian register's Latin spelling is "G ROX", legal form EOOD).

Before this program, every release ever shipped `-unsigned`: corporate
ESET/Defender quarantined the wizard as a "downloader trojan" (rc.28 BLOCKER-10),
AppLocker/WDAC publisher rules were impossible, Gatekeeper blocked the `.pkg`
outright, and the signing blocks in CI gated on a `WIN_CODESIGN_PFX_BASE64`
secret that could never be filled — the CA/Browser Forum has required HSM-held
keys for publicly-trusted code signing since June 2023, so no CA issues a PFX.

## Requirements

- **R1 — Windows chain of trust with zero key material in the repo.** Azure
  Artifact Signing over GitHub OIDC: certs minted on demand from a Microsoft
  HSM (~3-day leaves ⇒ RFC3161 timestamping mandatory), CI authenticates via a
  federated credential, configuration is seven repo *variables*, no secrets.
- **R2 — Sign the payload, not just the wrapper.** `meshharbord.exe` +
  `meshharbor-shim.exe` (installs as `meshharbor.exe`) signed BEFORE `cargo wix`
  harvests; third-party DLLs (wintun, VC-CRT) staged AFTER signing and asserted
  to keep their original signers.
- **R3 — Signedness is verified, never inferred.** `signtool verify /pa /all`
  + timestamp presence + expected-subject check after every signing call; the
  `-unsigned` filename suffix (computed from secret *presence*) retired.
- **R4 — A release tag that would ship unsigned FAILS.** `require` gate defaults
  true on tags; dispatch rehearsals stay green with warnings.
- **R5 — Version identity.** `meshharbord.exe`/`meshharbor.exe`/`meshharbor-shim.exe`
  embed VERSIONINFO (CompanyName=G ROX LTD, FILEVERSION = the MSI
  `MAJOR.MINOR.RC` remap); MSI `Manufacturer`, deb `maintainer`, Tauri
  `publisher` all agree with the certificate subject.
- **R6 — Linux/supply chain.** Detached GPG `.asc` per asset + the public key
  published in-repo and re-exported with every release; SLSA provenance
  attestations on all publish jobs. (`dpkg` doesn't verify signatures — the
  `.asc` is for humans/scripts and for the updater's pinned-key check, not
  apt-level trust; a signed apt repo stays deliberately out of scope.)
- **R7 — macOS identity.** All-or-nothing Apple credential gate; verify via
  `stapler validate` + `spctl -a` (the end-user Gatekeeper path); wizard ships
  a stapled `.app` inside the unchanged tarball name; bare tunnel CLI =
  notarised, unstapleable by design. Until the Developer ID exists: a **stable
  self-signed identity** whose designated requirement is byte-identical across
  releases, so macOS TCC grants survive updates.
- **R8 — Free rehearsal path.** `signing_mode=local` exercises the *identical*
  sign→verify→gate code with a self-signed cert imported into the runner's
  trust stores; GPO/Intune recipes unblock corporate pilots pre-cert.
- **R9 — Operator tooling + runbook.** `scripts/signing/00..90` (Azure
  onboarding, the portal-only identity-validation bridge, OIDC wiring, smoke
  sign, Apple/D-U-N-S/GPG setup, post-release verifier); `docs/code-signing.md`.

## Key design (as shipped; anchors against master)

- **Composite actions**: `.github/actions/sign-windows` (modes
  `auto|azure|local|off`; resolve→sign→verify→report; empty/missing file sets
  are hard errors — never silently sign a smaller set) and
  `.github/actions/sign-macos` (all-or-nothing gate; partial credentials used
  to publish signed-but-unnotarised pkgs with no warning). Both pinned by
  commit SHA where they call third-party actions.
- **Ordering invariant** (`release-agent.yml`, build-windows): payload signing
  sits after `encoder-smoke` (fail before spending a signature) and before the
  wintun/VC-CRT staging (third-party DLLs structurally can't be re-signed);
  **nothing after payload signing may `cargo build`** — a relink strips
  signatures silently. CI asserts wintun still says `WireGuard LLC` and
  `vcruntime140.dll` still says Microsoft.
- **Federated-credential reality**: the tenant rejects wildcard
  (`refs/tags/*`) subjects on both Graph v1.0 and beta, so the FIC is bound to
  the GitHub **`release` environment** — every azure-signing job carries
  `environment: release`; removing that line breaks tag signing.
- **Version-info mechanics**: `embed_resource::compile_for` (per-binary
  `rustc-link-arg-bin`), never winres/winresource whose `link-lib` directive
  leaks a second RT_VERSION into the Tauri EXEs that depend on these crates.
- **Identity facts**: Azure identity validation Completed for G ROX LTD
  (id `2390bcea-a3d5-4919-a624-cb209c875bf7`, valid to 2028-11-21); account
  `meshharborsigning` + profile `meshharbor-public-trust` in **polandcentral**
  (westeurope refused new-subscription resources; free-trial subscriptions are
  refused — PAYG required). Cert subject `CN=G ROX LTD, O=G ROX LTD,
  L=Pazardzhik, C=BG`; `AZURE_SIGNING_EXPECT_SUBJECT` locks it in CI.
- **GPG key shape**: ed25519 certify-only primary
  `D654B016256FD92A81634A0E2AD1E9F025973A7F` + `[S]` signing subkey (only the
  subkey secret reaches CI), expires 2028-08-22; pubkey committed at
  `scripts/signing/gpg/meshharbor-release-pubkey.asc`; the Linux/macOS updater
  verifies `.asc` against the key **pinned in the binary** (a key fetched from
  the release would be the same-channel failure as the SHA256).
- **Apple / D-U-N-S**: D&B already held a number for the entity —
  **524365169**, legal name "G ROX EOOD" (the register's own form; enrolment
  must match D&B character-for-character, so macOS identity reads EOOD while
  Windows reads LTD — same entity). Org enrolment 5XS5WN8R99 submitted
  2026-08-19 with authority-verification documents (registry excerpt
  „Актуално състояние" ЕИК 205174895 + owner self-attestation letter — a sole
  owner-manager has no employment verification).

## Acceptance criteria (all field-verified)

- [x] CI signs via Azure with OIDC and *verifies* — acceptance run
  `32640941995` (`signing_mode=azure require_signing=true`): payload
  `meshharbord.exe`/`meshharbor-shim.exe`, both MSIs, desktop EXE all
  `[G ROX LTD, timestamped]`, `signed + verified … mode=azure`.
- [x] Third-party signatures survive: `wintun.dll signer: WireGuard LLC
  (status=Valid)` asserted in the same run.
- [x] A real signed release shipped to the fleet: first at
  `agent-v0.3.0-rc.453`; the updater additionally verifies publisher
  (`WinVerifyTrust` + subject contains G ROX LTD) and binds manifest version to
  the signed MSI's ProductVersion (anti-rollback).
- [x] Unsigned-on-tag is impossible: `require` gate fails the job (negative
  test: `signing_mode=off require_signing=true` dispatch fails as designed).
- [x] GPG `.asc` + pubkey publish with every release; agent-side **pinned-key
  verification live-proven ×2** (rc.481/rc.482 macOS updates logged
  `installer .asc verified against the pinned release signing key`).
- [x] SLSA provenance attestations on every asset
  (`gh attestation verify <asset> --repo jk-zhang-meta/MeshHarbor`).
- [x] macOS interim identity stable across releases: designated requirement
  `identifier "fans.itachi.meshharbor.agent" + cert root H"b2a06501…"` byte-identical
  rc.479→482; TCC Screen-Recording grant survived updates (operator-confirmed
  on rc.482: "screen worked directly", no re-grant).
- [x] Apple Developer ID + notarisation live end-to-end — enrolment 5XS5WN8R99
  completed 2026-09-08 (team G ROX EOOD, `4TG7586MY5`; Developer ID Application
  + Installer on the G2 Sub-CA). Field-verified on a real Mac against the
  **published** `.pkg` with quarantine set: `spctl -a -vvv -t install` →
  `source=Notarized Developer ID`
  ([result](https://github.com/jk-zhang-meta/MeshHarbor/issues/778#issuecomment-5589571740),
  [on the published artifact](https://github.com/jk-zhang-meta/MeshHarbor/issues/778#issuecomment-5589756486)).
  The first run with real credentials was refused as `Invalid` (#1521, fixed).
  *Ticked 2026-09-25: verified on 09-08, left unticked at the close.*
- [x] Docs, in the house style and linked from `docs/README.md` (the
  docs-before-close rule, #1401): `docs/code-signing.md` — §2b's live status
  records all three platforms (it said Apple was "still pending" two weeks
  after it went live), §4 gains a diagram of the signing chain and both of its
  verifiers, §7b describes the updater's pinned-key `.asc` gate as built (it
  described it as unbuilt) and the downgrade that stays open on Linux/macOS,
  and §9 records the one name no sweep can align (`G ROX EOOD`).
  *Added 2026-09-25, after the close: the verification-debt guard (#1598) found
  FR-7 closed with no docs criterion.*

## Out of scope

- Signed apt repository (`InRelease`) — deferred until an apt channel exists.
- Signing the manifest itself (version+url+hash attested as a unit) — the
  per-artifact signature + ProductVersion binding closes the practical gap.
  ⚠️ *(2026-09-25) For the **MSI** only: a `.pkg` or `.deb` is authenticated by
  its pinned-key `.asc` but has no version binding, so the downgrade stays open
  on Linux/macOS — `docs/code-signing.md` §7b.*
  *(2026-10-18) Closed there too by FR-97 P6a: the `.deb`, `.pkg` and tarball
  each carry their version inside the signed bytes, and the updater binds it to
  the tag (`docs/code-signing.md` §7b).*
- EV/SmartScreen instant reputation — does not exist anymore (removed 2024);
  reputation accrues per publisher across releases.

## Field-verification log

| Date | Event |
|---|---|
| 2026-08-15 | Pipeline built + rehearsed with self-signed cert (29 local checks; `-Include`/`-LiteralPath` folder-sweep bug caught by tests) |
| 2026-08-19 | Azure identity validation submitted (portal-only; org vetting ignores billing-account type, `orgBillingMode:None`) |
| 2026-08-22 | Validation **Completed** (3 days); profile + OIDC wired; first real signature from dev box: `signtool verify /pa` PASS, subject G ROX LTD |
| 2026-08-22 | Near-loss recovered: the CI work existed only in a mislabeled stash; re-landed on rc.448-era master adapted to P3e (shim payload) — PR #599 |
| 2026-08-23 | GPG key minted + secrets set; **PR #599 merged**; acceptance run 32640941995 all-green under the hard gate |
| 2026-08-24 | First signed release `agent-v0.3.0-rc.453`; updater publisher-verify + anti-rollback binding land |
| 2026-08-25/26 | GPG `.asc` mandatory + pinned-key verify (#724, #727); macOS stable self-signed DR solves the TCC wipe (#729/#737/#740) |
| 2026-08-26 | Operator confirms on rc.482: TCC survived the update chain; pinned-GPG verify proven twice in the field |
| 2026-09-08 | Apple enrolment 5XS5WN8R99 completes; Developer ID Application + Installer issued (G2 Sub-CA, to 2031-09-09). First real run refused as `Invalid` (#1521, fixed). **Field-verified on a real Mac**: the published `.pkg`, quarantine set, `spctl` → `source=Notarized Developer ID` ([#778](https://github.com/jk-zhang-meta/MeshHarbor/issues/778#issuecomment-5589756486)) |
| 2026-09-25 | Record caught up. The verification-debt guard (#1598) found FR-7 closed with the Apple criterion unticked and no docs criterion. Ticked against the 09-08 evidence; `docs/code-signing.md` brought up to what shipped — it still called Apple "pending" and the updater's pinned-key gate unbuilt |
