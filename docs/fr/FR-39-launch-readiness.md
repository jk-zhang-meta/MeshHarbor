# FR-39: The product is unfindable — repository metadata, README, comparison docs, and a way for a visitor to stay in touch

> **CLOSED 2026-09-01** — issue #951 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

Status: **P1–P6 implemented; field-verification pending** (2026-08-29). Tracking issue: `FR-39` (#951).
Spec on master up front; the work is known and mostly mechanical.

## The measurement that motivates it

Roomler ships. Roomler is not findable. Measured 2026-08-29, all of it from public surfaces:

| surface | what it says today |
|---|---|
| GitHub repo description | *"Real-time team collaboration with chat, video conferencing, and AI transcription"* — the pillar this project deliberately demoted to third place in `#490`. Remote desktop and overlay networking are not mentioned. |
| GitHub topics | `axum` `chat` `collaboration` `mediasoup` `mongodb` `real-time` `rust` `saas` `video-conferencing` `vue3` `vuetify3` `webrtc`. Nothing for remote desktop, WireGuard, mesh, VPN or NAT traversal. |
| GitHub stars / forks | **0 / 0**, on a public repository with 577 releases since `agent-v0.1.0` (2026-04-17). |
| Web search for the product | returns the **retired** `roomler.live` identity, still described as a chat-and-video platform. FR-23 301'd the domain; search engines still carry the old description. |
| `roomler.ai` landing page | has no email capture of any kind (`ui/src/views/LandingView.vue` — no newsletter, no waitlist, no changelog subscribe). A visitor who does not register on the spot leaves no trace and cannot be reached again. |
| Self-hosting the server | **there is no path.** `docker-compose.yml` brings up *dependencies only* (Mongo/Redis/MinIO/coturn) — it does not run the application — and **no container image is published anywhere** (no workflow pushes to GHCR or Docker Hub). `LICENSING.md` promises "you can self-host all of it, free, on unlimited devices, forever"; the licence delivers that, the tooling did not. |
| Self-hosted software directories | absent from awesome-selfhosted (its *Remote Access* category holds 14 projects), awesome-sysadmin, AlternativeTo, SaaSHub, LibHunt. |

The category itself is demonstrably active — Hacker News gave a comparable open-source
mesh product 741 points in February 2026, and an open-source remote-desktop product
421 points — so this is a discovery failure, not a demand failure.

Two of these are worse than merely absent. The repository description **actively
mis-sells**: every directory, aggregator, search result and link preview reads that one
line first, and it advertises the wrong product. And the missing email capture is not a
marketing nicety — it is the difference between an audience that compounds and a series
of one-day spikes, which is a property that cannot be retrofitted onto traffic that has
already been and gone.

## Goal

A stranger who arrives at the repository or the landing page can say what Roomler is
within ten seconds, run it within ten minutes, and **leave an address without creating an
account** — so that interest which does not convert immediately is not lost permanently.

## Key design

1. **Repository metadata** (`gh repo edit`). Description names the two lead pillars and the
   licence posture. Topics carry the terms the audience actually searches:
   `remote-desktop`, `wireguard`, `mesh-vpn`, `overlay-network`, `tailscale-alternative`,
   `teamviewer-alternative`, `rustdesk-alternative`, `zero-trust`, `nat-traversal`,
   `socks5`, `self-hosted`. GitHub topic search is a primary discovery surface for this
   audience and the repository is absent from all of it. No code; recorded here because
   it is load-bearing and invisible in `git log`.

2. **A social preview image** (1280×640). This is the card every link to the repository
   renders — on Hacker News, Reddit, Slack, X. Derived from `docs/assets/hero-mesh.svg`
   so it matches the README and the landing hero rather than inventing a third identity.
   ⚠️ GitHub exposes **no API** for the social preview; the file is generated in-repo
   (`docs/assets/social-preview.*`) and uploaded once through repository settings.

3. **README lead rewrite.** The one-liner, then a demo, then the exact self-host
   quickstart — in that order, above the pillar sections. The current README opens well
   but buries `docker compose up -d` under ~150 lines of capability tables, and
   awesome-selfhosted's own criteria require *working installation instructions* while
   r/selfhosted's rules require a promoted project to be production-ready **with docs**.
   This audience runs the quickstart; a `docker compose up` that fails on a clean machine
   is a launch-ending comment.

4. **Comparison documents** (`docs/compare/`): Tailscale, RustDesk, TeamViewer,
   MeshCentral, NetBird. These are the literal queries the audience types, they are
   permanent, and they are the linkable ammunition for answering questions in public.
   Written to be *fair* — each names where the other product is better — because this
   audience checks, and a comparison that only flatters its author is read as marketing
   and discounted entirely.

5. **Email capture** — new `subscribers` collection + three public routes, mirroring the
   shape of the existing token-capability routes (`public_consent_routes`,
   `crates/api/src/lib.rs:463`), which take no auth extractor because an unguessable token
   *is* the capability:
   - `POST /api/subscribe` — `{ email, source }`. **Always answers 202**, whether the
     address is new, already subscribed or malformed-but-plausible: a response that
     distinguishes them is an account-enumeration oracle against a `users.email` unique
     index that is also the account-linking key (see the email-ownership invariant in
     `CLAUDE.md`).
   - `GET /api/subscribe/confirm/{token}` — double opt-in.
   - `GET /api/subscribe/unsubscribe/{token}` — one-click, no auth, never expires.
   Unique index on `email`; `source` recorded so the channel that produced a subscriber is
   knowable later. ⚠️ **The unsubscribe token is minted at subscribe time, not at send
   time** — a list you cannot leave is not a list you may lawfully send to, and building
   the exit after the entrance is how it gets forgotten.

6. **Privacy Policy amendment.** The company is EU-incorporated; a new personal-data
   collection that the policy does not describe is a defect in the policy the moment the
   route ships. ⚠️ FR-23 found **three false claims** in this exact copy by drafting from a
   template rather than from the code — so the amendment states only what the
   implementation does.

## Phases

| phase | scope | kill switch |
|---|---|---|
| P1 | repository description + topics; social preview asset | revert `gh repo edit` |
| P2 | README lead: one-liner → demo → verified quickstart | — (docs only) |
| P3 | `docs/compare/` — five comparison documents | — (docs only) |
| P4 | `subscribers` model + DAO + the three public routes + rate limit | route not mounted |
| P5 | landing-page capture UI + Privacy Policy amendment | UI section removed |
| P6 | `docker-compose.selfhost.yml` + `.env.selfhost.example` + `docs/self-hosting.md` — a one-command self-host path | file is additive; nothing existing changes |

## Acceptance criteria

- [x] `gh repo view --json description,repositoryTopics` names remote desktop and mesh
      networking, and carries at least eight discovery topics — **done**, 20 topics live
- [~] the repository's social preview renders the product name and one-liner in a link card
      — asset generated (`docs/assets/social-preview.png`); **GitHub exposes no API, so the
      upload is an operator step** (Settings → General → Social preview)
- [~] the README's first screen carries the one-liner, a demo, and a quickstart that was
      run from scratch on a clean machine — one-liner and quickstart **done**; the demo is
      the operator step below, and the clean-machine run is unverified
- [x] `docs/compare/` holds five documents, each naming at least one thing the other
      product does better — **done** (Tailscale, RustDesk, TeamViewer, MeshCentral, NetBird)
- [~] `POST /api/subscribe` stores a subscriber and returns **202 for a fresh address and
      202 for an address already on the list**, indistinguishably — implemented and locked by
      `crates/tests/src/subscribe_tests.rs`, which **has not been run**: Docker was not
      available on the dev box, so the lane runs in CI (this PR touches `crates/tests/**`)
- [~] the unsubscribe link in the stored record works with no session and no account —
      same status as above: asserted, not yet run
- [x] the Privacy Policy describes the subscriber collection, and every sentence of that
      description is true of the code that ships with it — **done** (§2.14 + retention),
      written from the implementation rather than from a template
- [ ] `docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d --build` brings up a working instance on a clean machine, and `/health` answers 200 **(operator — needs a clean box and a 10–20 min build)**
- [ ] a 60–90 s demo (enroll → browser desktop → `roomler ssh` → `roomler forward`) exists
      and is embedded in the README **(operator — needs a real capture session)**

## Open decisions

- **Whether the confirmation email sends at all in P4.** The list is worthless if it cannot
  be mailed, but list *sending* is a separate program; P4 stores the token and attempts the
  send through the existing mail path, and an unconfirmed row is still a row.
- **Where the comparison documents ultimately live.** `docs/` is crawlable through GitHub
  today, which is enough to be useful and to link from. Ranking them on `roomler.ai`
  needs server-side rendering, which the SPA does not do — a separate FR if it is wanted.

## Out of scope

- Campaign tactics, channel timing and post copy. Those are not engineering artifacts and
  deliberately do not live in a public repository.
- Newsletter *sending*, templates, and any analytics beyond the `source` field.
- SSR / prerendering for marketing pages.
- Renaming the repository or the product.

## Field-verification log

| date | what was checked | result |
|---|---|---|
| 2026-08-29 | baseline: description, topics, stars, landing capture, directory presence | recorded above |
| 2026-08-29 | **P1** repo description + 20 topics | live; `gh repo view` confirms |
| 2026-08-29 | self-host compose renders, and fails fast without a secret | `docker compose config` exit 0 with secrets, exit 1 + the generation hint without |
| 2026-08-29 | config keys the compose sets actually exist | `auth.auto_verify`, `s3.enabled` in `settings.rs`; the production JWT refusal at `crates/api/src/main.rs:32` |
| 2026-08-29 | two draft claims checked against code and **corrected** | registering creates no organization (`auth.rs:140` — the web form sends no `tenant_name`); agents update from upstream GitHub releases, not a self-hoster's builds (`agent_release.rs`) |
| 2026-08-29 | UI typecheck + unit tests | `vue-tsc --noEmit` clean; **901 tests / 39 files pass** |
| 2026-08-29 | `cargo check -p meshharbor-api` (WSL) | clean |
| | `crates/tests/src/subscribe_tests.rs` | **not run locally** — no Docker on the dev box; runs in CI |
| | one-command self-host on a clean machine | **operator** — needs a clean box and a 10-20 min build |
| | 60-90 s demo recorded and embedded | **operator** — needs a real capture session |
| | social preview uploaded | **operator** — no GitHub API for it |
| 2026-08-30 | **CI, full suite** on PR #957 | 9 of 10 lanes pass — Rust checks (fmt + workspace clippy `-D warnings`), Frontend, Licence split, Retired-name audit, ffmpeg-encoder, Windows/macOS overlay, GitGuardian |
| 2026-08-30 | **Integration suite: 4 of 8 subscriber tests FAILED** | And the failure was in the TEST, not the route. Both link routes answer `303` to `frontend_url`, which in a test is the default `http://localhost:5000` — a port nothing listens on — and a default `reqwest::Client` **follows redirects**, so a correct response died as `ConnectionRefused` against port 5000. ⚠️ Worth remembering shape: the panic names the *test server's* port in the URL and a *different* port in the error, which is the tell. Fixed by stopping at the hop with `redirect::Policy::none()` and asserting the `Location` — a strictly better assertion, since it pins where the link actually sends a human (`subscribe=confirmed`/`unsubscribed`/`invalid`), which following the redirect silently discarded |
| 2026-08-30 | the four that PASSED are the ones that matter most | `a_known_address_is_indistinguishable_from_a_fresh_one` (the membership-oracle control), plus fresh-address storage, malformed-input handling and address normalisation — none of which follow a link |
| 2026-08-30 | licence-split lane caught a real mistake | `docs/assets/social-preview.html` carried `AGPL-3.0-only` because I hand-copied the header from neighbouring Rust files; `docs/` is **CC-BY-4.0**. Fixed by `scripts/apply-spdx.sh` rather than by hand, so placement matches every other file |
| 2026-08-30 | a timing oracle found by reviewing my own design | `POST /api/subscribe` awaited the SMTP round trip inline, so a fresh address answered measurably slower than one already on the list — leaking through latency exactly what the uniform 202 refuses to leak. The send is now detached |
