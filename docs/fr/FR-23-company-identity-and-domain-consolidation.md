# FR-23: Company identity on the site, and one product on both domains

**Issue:** [#827](https://github.com/gjovanov/roomler-ai/issues/827)
**Status:** **CLOSED 2026-09-08** — Apple enrolment 5XS5WN8R99 resolved (Team `4TG7586MY5`,
G ROX EOOD); every criterion met or explicitly withdrawn (phase 4 skipped, phase 5 shipped
as a 301). ⚠️ Apple states no reason for a review clearing, so the wrong phone number is the
best available explanation for the fourteen-day silence, **not a proven cause** — both
defects were real and are fixed, which is what this FR can claim.
**Related:** [FR-7](FR-7-signed-releases.md) (signed releases — the Apple half is what this unblocks)

## Goal

Make the legal entity behind Roomler **publicly verifiable**, correct the company
phone number everywhere it was recorded wrong, and retire the obsolete
`roomler.live` deployment so that both company domains serve the current product.

The immediate driver is Apple Developer Program enrolment **5XS5WN8R99**, which
has sat in review since 2026-08-19. But the imprint is not merely an Apple
workaround — an EU company operating a public service is expected to publish one,
and the phone number is wrong in systems that matter independently of Apple.

## Root cause / field evidence

### 1. The phone number was wrong, and it is my error

The Azure billing profile displayed `0035987711888`. Reformatting that into the
Apple enrolment form and the signed letter of authority produced
**`+359 87 771 1888`** — digits transposed *and* one added. The correct number is
**`+359 87 711 8883`** (national `877118883`).

Apple's organisation verification commonly includes a **call to the company
number on file**. A dead number is the single strongest available explanation for
a review that received its documents (confirmed 2026-08-22 21:47) and then went
silent for five business days.

⚠️ This is not a substring edit: `877711888` → `877118883`. A
`sed 's/7711888/7118883/'` leaves a stray `7` and produces a *different* wrong
number. The whole national part must be replaced.

Measured spread (2026-08-28, `rg` over the working tree):

| Location | Occurrences |
|---|---|
| `scripts/signing/55-apple-duns.sh` | 2 — line 48 (comment), line 63 (field sheet) |
| `apple-authority-letter.md` in the **repo root** | 2 — untracked, **not gitignored** |
| `Dropbox/GROX/Apple enroll/*.md` | copies of record |
| Apple enrolment record 5XS5WN8R99 | submitted — operator action |
| Azure billing profile | `0035987711888`, also wrong (8 digits; a BG mobile is 9) |

The repo-root `apple-authority-letter.md` is a second, unrelated defect: an
untracked file that `git add -A` would have committed company and personal
documents into a public repository.

### 2. Nothing publicly linked either domain to the company

Apple's enrolment requirements state that the organisation's website must be
publicly available and **the domain name must be associated with the
organisation**, with a work email on that domain. The enrolment declares
`goran.jovanov@roomler.live`.

Checked 2026-08-28 — `G ROX`, `EOOD` and `205174895` appear **nowhere** in `ui/`.
`TermsView.vue` and `PrivacyPolicyView.vue` name only the product and give
`legal@roomler.ai` / `privacy@roomler.ai`. There is no imprint, no legal-notice
block, and no company registration anywhere on either site.

So a reviewer tracing **Goran Jovanov → @roomler.live → G ROX EOOD** finds no
public evidence for the last hop. D&B proves the company exists; the register
excerpt proves he owns and manages it; nothing proved the *domains* are its.

Compounding it: the work-email domain (`roomler.live`) served the **legacy**
product (`<title>roomler.ui</title>`), while the current product and every
published contact address live on `roomler.ai`.

### 3. Three-way name reconciliation

The register keeps the name in Cyrillic as „Г РОКС" ЕООД and records **G ROX** as
the registered Latin spelling; D&B and the enrolment say **G ROX EOOD**. A
reviewer without Bulgarian has three strings and no stated relationship between
them. The imprint states it explicitly.

⚠️ Separately and deliberately **out of scope**: the Windows code-signing
certificate subject reads **G ROX LTD**. Same entity, a fourth rendering. Aligning
it would require a new Azure identity validation (the current one is valid to
2028-11-21), so it stays as-is and is recorded here rather than silently endured.

## Key design

### Phase 0 — phone

Replace the whole national part in `scripts/signing/55-apple-duns.sh:48,63`;
delete the untracked repo-root letter (the copy of record is in Dropbox, verified
byte-identical before deletion).

### Phase 1 — imprint

`ui/src/views/legal/ImprintView.vue`, following the existing legal-page pattern
exactly — `<v-theme-provider theme="light">` → `.legal-page` → the 800px
`.legal-container`, `text-h5` section headings, `legal-muted` body, the identical
scoped style block, and an empty `<script setup>` with no `lang="ts"`. These pages
are deliberately **not** i18n'd; `en.json` has no legal namespace.

Route at `ui/src/plugins/router.ts` beside `/privacy` and `/terms`, carrying **no
`meta`** — which is what makes those two unconditionally public, and the imprint
must be reachable signed-out.

Reach: `LandingView.vue`'s footer is the **only** footer in the app (`App.vue` is
just `<v-app><router-view/></v-app>`), so its Legal column gets the link and its
copyright line names the operating company. Terms §16 and Privacy §11 each gain a
company block; on Privacy that block also names the **data controller**, which
GDPR requires and which was missing.

### Phase 5 — roomler.live serves the current app

Mostly free. `files/nginx-pod.conf:3` is `server_name _` (a catch-all), the SPA is
entirely origin-relative, and the API never reads the `Host` header.

**The one dangerous change is `app.cors_origins`.** `crates/api/src/origin.rs:35`
resolves the origin policy, and `:44-49` adds `frontend_url` **only when the
configured list is empty** — an explicit list *replaces* the default rather than
extending it. That is locked by
`an_explicit_list_replaces_the_frontend_default` (`origin.rs:157`), whose comment
states the intent: "an operator who enumerates origins is stating the whole set."

This gates **two** things, which is why `origin.rs` exists at all: the CORS layer,
and the `/ws` cookie handshake (`crates/api/src/ws/handler.rs:109`, via
`origin_is_ours` at `:146-154`). A WebSocket handshake is not subject to CORS, so
this is the check standing between an attacker's page and an authenticated socket.

⇒ both origins must be trusted. Trusting only `roomler.live` breaks `roomler.ai`.
The `/ws` check applies **only to the cookie path** (`handler.rs:88-113`) — a
`?token=` client sends a credential it had to obtain, and native clients send no
`Origin` at all — so agents and tunnel clients are unaffected, while every
**browser session** on an untrusted origin loses its socket: chat, notifications,
presence and RC signalling all die.

⚠️ **Measured 2026-08-28: "list both in the configmap" is IMPOSSIBLE today.**
`settings.rs:584` is `Environment::default().separator("__").prefix("MESHHARBOR")`
with **no `list_separator`**, and `app.cors_origins` is `Vec<String>` — so a
scalar env var deserialising into a sequence *fails outright*
(`invalid type: string, expected a sequence`) and the API would **refuse to
boot**. The repo already knows this: `jwt.previous_secrets` is deliberately a
`String` for exactly this reason (`settings.rs:441-447`), and the e2e overlay's
configmap carries the same warning.

Two real paths, neither of them "just set the configmap":

- **A — mount a file.** `Settings::load` also reads
  `File::with_name("config/local")` (`settings.rs:582`) and the Dockerfile's
  runtime stage sets **no `WORKDIR`**, so CWD is `/` and a ConfigMap at
  `/config/local.toml` is read. No code change. ⚠️ But the source is
  `required(false)`, so **a wrong path is a silent no-op** — the API boots, the
  trust set stays `roomler.ai`-only, and the sole symptom is that browser
  WebSockets on `roomler.live` fail. Silent-on-misconfiguration is a bad property
  for the control gating ambient-credential auth.
- **B — two lines, recommended.** Scope list parsing to just this key:
  `.list_separator(",").with_list_parse_key("app.cors_origins")` (config 0.14.1
  supports both). Then `MESHHARBOR__APP__CORS_ORIGINS` works in the existing
  configmap and a malformed value fails **loudly at boot**. Scoped, so no other
  field's parsing changes — a global `list_separator` would silently split any
  string containing a comma.

⚠️ Order matters if B is taken: deploy the code first (a no-op while the env var
is unset), **then** add the configmap key in a separate gitops commit. Doing both
at once means an old pod that restarts mid-roll reads a key its binary cannot
parse and crash-loops.

### ⚠️ Sequencing correction (found during phase 4's inventory)

Phases 4 and 5 as written are **ordered wrong**. `roomler.live.conf` currently
proxies the *old* app (`proxy_pass http://10.10.10.11:30030`), so tearing that
down first makes the apex **502** — on the very domain whose credibility the
Apple review turns on. **Cut `.live` over first, verify, then tear down.**

### Phase 4 — what is actually there

| | |
|---|---|
| ArgoCD app | `roomler-old` → `github.com/gjovanov/roomler-deploy.git`, `k8s/overlays/prod`, `main` |
| Registered in | app-of-apps `github.com/gjovanov/argocd-apps.git`, path `apps`, `recurse: true` |
| Namespace | `roomler` (179 d) |
| Workloads | deployments `janus`, `redis`, `roomler`; statefulset `mongodb`; 4 running pods |
| PVCs / PVs | `mongodb-data` + `roomler-uploads`, 5Gi each → **hostPath**, **reclaim=Retain**, nodeAffinity **`k8s-worker-2`** |
| On disk | `/data/roomler/mongodb`, `/data/roomler/uploads` |

⚠️ The namespace is **not** owned by the Application, so pruning leaves
`ns/roomler` behind. ⚠️ Both PVs are `Retain`, so they outlive the prune and the
hostPath dirs outlive the PVs — `/data/roomler/*` must be removed explicitly on
that node, and must not be confused with the **current** product's
`/data/roomler-ai/*` on the same node. ⚠️ The parent app runs `prune: false`
deliberately, so deleting `apps/roomler-old.yaml` does not cascade.

## Phases

| # | Phase | Kill switch | Status |
|---|---|---|---|
| 0 | Phone rectification | revert one commit | ✅ shipped |
| 1 | Imprint page + company blocks + footer | revert; route is additive | ✅ shipped |
| 2 | FR + PR | — | ✅ shipped |
| 3 | Deploy | previous image tag | ✅ shipped + field-verified (`v20260828-de59383da2fe`) |
| 3b | Send Apple the correction | — | ✅ done — enrolment cleared 2026-09-08 |
| 4 | Delete the obsolete `roomler-old` app | — | 🚫 **SKIPPED** by the operator — the old app keeps running; its `janus`/`coturn` subdomains still depend on it |
| 5 | `roomler.live` → **301** to `roomler.ai` | restore `roomler.live.conf.bak-pre301-*`, `nginx -t`, reload | ✅ shipped + field-verified |
| 6 | Legal pages describe all three pillars | revert one commit | ✅ shipped (#835) |

## Acceptance criteria

- [x] The wrong number survives **nowhere** in the repo, and the correct one is present
- [x] The repo-root `apple-authority-letter.md` is gone
- [x] `/imprint` renders signed-out, naming G ROX EOOD, UIC 205174895, the registered office, the representative and the corrected phone
- [x] Terms and Privacy name the entity; Privacy names the **data controller**
- [x] The landing footer links the imprint and names the operating company
- [x] `bun run build` (incl. `vue-tsc --noEmit`) and `bun run test:unit` pass
- [x] `https://roomler.ai/imprint` is live — verified against the **shipped bundle**, not the source
- [x] Apple has the corrected number and the imprint URL
- [x] ~~The `roomler-old` namespace … are gone~~ — **withdrawn**: the operator chose to skip the teardown, and `janus.roomler.live` / `coturn.roomler.live` still depend on that namespace
- [x] `https://roomler.live` **301s to `roomler.ai`**; `roomler.ai` verified unaffected (200, title `Roomler`), and every co-hosted vhost re-checked
- [x] Terms and Privacy describe **all three pillars**, and the Privacy Policy's false `localStorage` claim is gone
- [x] Apple enrolment 5XS5WN8R99 resolves — **2026-09-08**, Team `4TG7586MY5`. Both Developer ID certificates issued; `agent-v0.4.92`'s `.pkg` notarised, stapled, and Gatekeeper-accepted on a real MacBook **with the quarantine attribute set** (the Finder path — `curl | install.sh` never sets quarantine and so proves nothing)
- [x] **Docs** — this FR's deliverable *is* user-facing documentation (`/imprint`, Terms, Privacy), so the "docs before close" standing rule is satisfied by the pages themselves; there is no `docs/*.md` subsystem to describe and none was invented to tick a box

## Open decisions

- **OAuth on `roomler.live` will fail** and is shipped that way unless mitigated.
  `oauth.base_url` is a single string, so the callback lands on `roomler.ai` while
  the `oauth_state` CSRF cookie was set **host-only** on `roomler.live` — the
  double-submit check refuses, correctly. Password login is unaffected. Cheapest
  mitigation is an edge redirect of `/oauth/*` on `.live` to `.ai`.
- **Analytics mis-attribute on `.live`** — `ui/index.html:8` hardcodes
  `data-domain="roomler.ai"`.
- **Whether `roomler.live` should serve the app at all, or simply 301 to
  `roomler.ai`.** This was written as a footnote and implementation has promoted
  it to the live decision, on three facts that were not known when the phase was
  planned:
  1. **It is not config-only** — either a code change or a silently-failing file
     mount (above).
  2. **OAuth on `.live` stays broken either way.**
  3. **`roomler.live` is not a spare domain.** It hosts live, unrelated services
     as subdomains — `bauleiter`, `regal`, `janus`, `coturn`, `neko`, `ping`,
     `asterisk`, `audio-waveform`, `scws`. Only the **apex** is the obsolete
     product, and only the apex may be touched.

  And the phase's original Apple rationale has already been delivered by phase 1:
  the imprint names `roomler.live` as company-operated, so a reviewer can close
  the loop today. What actually remains is *"don't serve an obsolete product on
  our own domain"* — for which a **301 is the cleanest answer**, needs one nginx
  file, no code, no configmap, and composes naturally with phase 4 (once the old
  app is gone there is nothing left to proxy). Serving the app remains entirely
  doable via B; the trade is recorded rather than quietly decided.

## Out of scope

- Aligning the code-signing certificate subject (`G ROX LTD`) with the register
  form — needs a fresh Azure identity validation.
- i18n for the legal pages — none of the three is translated today.
- **Enrolling agents against `roomler.live`.** Agent identity is
  `(server_url, tenant_id)`, so the same tenant reached via `.live` registers as a
  *second org* with its own WireGuard identity. The installer scripts default to
  `https://roomler.ai` and the dashboard passes `--server ${origin}` — those
  defaults stay untouched.

## Phase 6 — the legal pages described a product that no longer existed

Both pages were dated **February 2026** and defined Roomler as *"a real-time
collaboration platform … chat, video conferencing, file sharing, and multi-tenant
workspace management"* — now one of three pillars, and the one carrying the least
risk. Remote desktop and the private mesh appeared **nowhere** in either document.

That is not an undersell; it is a gap in exactly the places a user takes on an
obligation. Terms gained three sections that did not exist — the **agent and
enrolled devices** (authority to install, administrative privilege, self-update,
host networking changes), **remote access and control** (unattended access as a
deliberate choice carrying its own notice obligations; sessions recorded as
events, not content), and the **private network** (subnet routers, exit nodes and
whose address traffic appears to come from, tunnels, default-deny). Acceptable
Use previously covered chat abuse and nothing else. `Microsoft` was a supported
sign-in provider listed nowhere. Ownership and governing law are now answerable
(**G ROX EOOD**, **Bulgaria**) because the imprint exists.

⚠️ **The Privacy Policy contained a false statement**: *"Roomler uses a JWT …
stored in your browser's `localStorage`."* Untrue since the cookie-only session
work (#680/#682/#690/#691) — local storage holds a boolean signed-in hint and
grid preferences. The policy was publishing a **worse security posture than the
product has**, in the document people read to find out. Corrected to describe the
`HttpOnly` cookie, with the reason.

The policy also gained a new **§3 "What we deliberately do not see"** — the
property that was missing entirely and is the best thing about the design: the
servers coordinate connections but never carry readable session data, and a relay
only ever moves ciphertext. Plus the previously-undisclosed categories (device
records, connection metadata, audit trails, crash reports *and their log tail*,
push subscriptions, self-hosted analytics with country-level geolocation) and
retention figures that match the **TTL indexes** rather than gesturing at plan
limits.

Every claim was checked against code rather than drafted from a template — the
discipline the repealed-ODR-link defect earned.

## Field-verification log

| Date | What | Result |
|---|---|---|
| 2026-08-28 | `rg` for the wrong number across the tree | 4 hits: 2 tracked (`55-apple-duns.sh`), 2 in an untracked repo-root letter |
| 2026-08-28 | `git check-ignore apple-authority-letter.md` | exit 1 — **not** ignored; `git add -A` would have published it |
| 2026-08-28 | `diff` repo-root letter vs the Dropbox copy | identical — safe to delete |
| 2026-08-28 | `rg 'G ROX\|EOOD\|205174895' ui/` | **zero hits** — the gap Apple cannot close |
| 2026-08-28 | Ledger vs GitHub issues | FR-1…FR-22 taken (FR-3 vacated); FR-20/#807 and FR-21/#809 have issues but no rows on master ⇒ claimed FR-23 |
| 2026-08-28 | Deployed `v20260828-de59383da2fe`; `grep -c imprint` on the **live main bundle** | **0 → 1** (`index-CaaVw1X0.js` → `index-CkmwLR-m.js`). The route did not exist in the shipped artifact before and does now |
| 2026-08-28 | Live lazy chunk `ImprintView-CuuvccrS.js` | all present: `G ROX EOOD`, `205174895`, `BG205174895`, `Plovdivska 110`, `Pazardzhik`, `Goran Jovanov`, `711 8883`, `roomler.live`, `РОКС` (UTF-8 survived the whole pipeline) |
| 2026-08-28 | Live `TermsView` / `PrivacyPolicyView` / `LandingView` chunks | each names the entity and links `/imprint`; Privacy carries `data controller` |
| 2026-08-28 | **Defect in my own imprint** | it cited the EU ODR platform, **repealed by Reg. (EU) 2024/3228, offline since 2025-07-20**. Confirmed live (`grep -c consumers/odr` → 1), removed in #830 |
| 2026-08-28 | `roomler.live` vs `roomler.ai` titles | `roomler.ui - roomler.ui` vs `Roomler` — the apex really is still the obsolete product |
| 2026-08-28 | `settings.rs:558` env source | no `list_separator` ⇒ `MESHHARBOR__APP__CORS_ORIGINS` would **crash the API at boot**, not merely be ignored. Phase 5 is not config-only |
| 2026-08-28 | `ws/handler.rs:88-113` | the origin check gates the **cookie path only** ⇒ agents unaffected, browser sessions on an untrusted origin lose every socket |
| 2026-08-28 | Cluster access | `kubectl`+`argocd` on the build host, kubeconfig at `/home/gjovanov/.kube/config`. The earlier "no kubeconfig" was wrong — it checked `/root` only |
| 2026-08-28 | **Phase 5 shipped as a 301.** `roomler.live` (http + https) | `301 → https://roomler.ai/`; `roomler.ai` **unaffected** (200, title `Roomler`) |
| 2026-08-28 | Co-hosted vhosts re-checked after the reload | `bauleiter`/`regal`/`asterisk`.roomler.live, `argocd.roomler.ai`, `purestat.ai`, `lgrai.app` all 200. `janus` 404 at `/` but **healthy** (`/janus/info` → 200). `ping` 502 — **pre-existing**, its backend `:4000` has zero listening sockets. `coturn` 000 — that conf has **no HTTPS server block**. nginx error log empty since reload |
| 2026-08-28 | `roomler.live` cert | wildcard `*.roomler.live`, **DNS-01 via Cloudflare**, valid to 2026-11-18 ⇒ a blanket redirect cannot break renewal |
| 2026-08-28 | `$tls1_3_early_data` map | was defined **twice** across `conf.d`; the surviving definition is `asterisk.roomler.live.conf`, the file that uses it |
| 2026-08-28 | Legal-page facts checked against code | `"microsoft"` is a real provider; `localStorage` holds only `SIGNED_IN` + grid prefs (so the policy's JWT claim was **false**); 90-day and 7-day TTLs exist in `crates/db/src/indexes.rs`; crash reports carry `hostname`, `pid`, `log_tail` |
| 2026-08-28 | Live legal chunks **before** the phase-6 deploy | privacy `JSON Web Token` → **1** (the false claim was live); `HttpOnly` → 0; terms `exit node` → 0; `Microsoft` → 0 |
| 2026-09-08 | **Apple enrolment 5XS5WN8R99 resolved.** Team `4TG7586MY5`, G ROX EOOD | Both Developer ID certificates issued; six `APPLE_*` secrets set; `agent-v0.4.92` `.pkg` notarised + stapled |
| 2026-09-08 | Gatekeeper on a real MacBook (26.6.2 arm64), **quarantine attribute set** | `accepted` · `source=Notarized Developer ID` · `origin=Developer ID Installer: G ROX EOOD (4TG7586MY5)` · `stapler validate` OK · `pkgutil` → *trusted by the Apple notary service* |
| 2026-09-08 | Close-out re-check of the **shipped bundle** (not the route) | `index-CWf4GqhQ.js` → 1 × `imprint`; `ImprintView-BJDZ-oN2.js` → `205174895`, `G ROX EOOD`, `711 8883`, `roomler.live` |
| 2026-09-08 | Close-out re-check of the redirect | `https://roomler.live/` → `301 Location: https://roomler.ai/`; `roomler.ai/` 200, `roomler.ai/health` 200 |
