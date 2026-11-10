# FR-12 — Onboarding tutorial ("Welcome tour")

**Issue:** [#788](https://github.com/jk-zhang-meta/MeshHarbor/issues/788)
**Status:** P1 + P2 + **P3 shipped and FIELD-VERIFIED** — the arc is complete

## Goal

A first-time user landing in a fresh org has no guidance: the product's real
shape (devices + remote desktop + private network + tunnels + ACLs + rooms/
calls/chat) is discoverable only by clicking around. Ship an in-app **Tutorial**
with the README's visual language (`docs/assets/*.svg` hero illustrations +
"In detail" tables) that (a) opens for new users, (b) walks each capability
with do-it-now steps deep-linked into the live UI, and (c) stays **callable
anytime** by already-onboarded users.

## Visual language (reuse, don't reinvent)

`README.md` already defines it: one illustrated SVG per pillar —
`docs/assets/hero-mesh.svg`, `remote-desktop.svg`, `private-network.svg`,
`collaboration.svg` — plus concise capability tables. P1 reuses these four
verbatim (imported into the UI bundle); P3 adds same-style smaller
illustrations for the finer chapters (ACL, calls, chat).

## Design

### Surface: a dedicated Tutorial view, not a modal carousel

Route `tutorial` under the tenant shell (`/tenant/{tid}/tutorial`), rendered
like the other full views (h1 + content; the AdminPanel shell pattern). A
left chapter rail + scrollable chapter body:

| # | Chapter | Hero | Do-it-now steps (deep links) |
|---|---------|------|------------------------------|
| 0 | Get started | hero-mesh | create/rename org → enroll first device (opens the Enroll dialog on /devices) |
| 1 | Devices | hero-mesh | enroll (device vs tunnel client), grid tour (search/columns/tags/display name), update/pin |
| 2 | Remote desktop | remote-desktop | Connect from the grid, consent modes, clipboard + file transfer, codecs note |
| 3 | Private network | private-network | overlay addresses + MagicDNS name (copy from the grid), `mh ssh <name>` |
| 4 | Tunnels | private-network | `mh forward` / SOCKS5 one-liners (copyable, org-scoped), declared routes |
| 5 | ACL & policy | private-network | tunnel ACL default-deny, overlay ACL modes, subnet-route approval (/network/acl) |
| 6 | Rooms & chat | collaboration | create a room, invite someone (deep link /invites), mentions/files |
| 7 | Calls | collaboration | start a call from a room, screen share, the call badge |

Each chapter = hero SVG + one short paragraph (README tone) + a 2–4 item
checklist whose items are REAL router links (never screenshots of buttons) +
an "In detail" table borrowed/condensed from the README section.

### Entry points

1. **First login, auto-open**: after login, if `localStorage
   meshharbor-tour-seen:<userId>` is absent AND the active org looks fresh
   (0 devices — `deviceStore.total === 0` — and ≤1 room), route to the
   Tutorial instead of the dashboard, set the flag on first render.
   Dismissible instantly (the flag persists); never auto-opens twice.
2. **Callable anytime** (the explicit requirement): a `?` help icon in the
   app bar (next to notifications) → Tutorial; plus a "Tutorial" item in the
   user menu. Both visible to every member forever.
3. **Empty-state CTAs**: the devices grid's and rooms list's empty states
   link to their matching chapter (`/tutorial#devices`, `#rooms`).

### Progress

P1: per-chapter "done" checkmarks in `localStorage`
(`meshharbor:tour-progress:<userId>` — the useGridColumns storage conventions).
P3 (optional): mirror server-side on the user profile so progress follows
devices.

### Explicit non-goals

- No overlay/spotlight walkthrough of the live UI in P1 (P2 evaluates a
  dependency-free spotlight for the 3 core flows: enroll → connect → forward).
- No videos; SVG + text only (bundle size, translatability).
- No server round-trips in P1 — the tutorial is fully static + router links.

## Phases / status

| Phase | Content | Kill switch | Status |
|-------|---------|-------------|--------|
| P1 | Tutorial view (8 chapters, 4 reused SVGs), app-bar `?` + user-menu entries, first-login auto-open, localStorage progress | auto-open reads one localStorage flag; the route/nav entries are plain UI | **shipped** — PR #797 |
| P2 | Spotlight micro-tours on the live pages (dependency-free): module-scoped step machine + ONE overlay in `AppLayout` + a `?tour=` entry | per-tour "skip", and the only Tutorial entry is one button | **shipped** — PR #1117 |
| P3 | Five new same-style SVGs (devices/tunnels/acl/rooms/calls) so no two chapters share artwork; server-side progress mirror | none needed (additive); the mirror is fire-and-forget, so the tutorial still works with the route unreachable | **shipped** — PR #1138 |

## P3 as built

### Artwork: eight chapters, eight illustrations

P1 deliberately reused the four README heroes, which meant Access control and
Private network showed the SAME picture, and so did Rooms and Calls. A reader
who sees a familiar illustration reasonably concludes they are back where they
started, so the sharing was not merely unpolished — it misinformed.

Five new SVGs in the same house style (760x400, `<title>` + `<desc>`, a
`prefers-reduced-motion` guard, no external assets):
`devices.svg` (a single-use token becoming a row in the device list, beside one
row that is offline so the list reads as a liveness view), `tunnels.svg`,
`acl.svg` (two flows allowed through a policy gate, one denied, with the audit
line underneath), `rooms.svg` (threads, mention, typing) and `calls.svg`
(shared screen + a filmstrip showing speaking / camera-off / muted).
`ui/src/assets/tutorial/collaboration.svg` was deleted with its last reference;
`docs/assets/collaboration.svg` is untouched and still serves the README.

Each was RENDERED and looked at rather than reasoned about, which is the only
reason four real defects were caught: the ACL deny row was invisible for most
of its animation cycle, its third service sat unconnected to anything, the call
filmstrip's speaking ring bled outside its tile and its level bars collided
with the name label, and `calls.svg`'s `<desc>` described four tiles where
three are drawn. None of those is visible in the source.

**Two guards, both shown to fail before being trusted**: no two chapters may
point at one asset (the message names the reused files), and every animated
illustration must carry a `<desc>` and a `prefers-reduced-motion` guard. The
second reads the SVG SOURCES via `import.meta.glob(..., '?raw')` rather than
the imported URLs, because what ships is what matters, and it asserts the glob
found something -- a glob whose path is wrong passes vacuously.

### Progress mirror: `PUT /api/user/tutorial`, read back on `/auth/me`

`users.tutorial` (`TutorialState { done, seen_at }`, `#[serde(default)]` so
every existing document deserialises), written by one dedicated route and read
on the boot response the client already fetches -- no second round trip.

Four decisions worth keeping:

- **Not folded into `update_profile`.** That route is the user-editable
  profile; this is app state the tutorial owns, and the DAO's positional
  signature was already at six arguments.
- **`done` REPLACES; the client UNIONS on seed.** A union on write would make
  un-ticking a chapter inexpressible -- the client sends a shorter list and the
  server keeps the longer one, silently. The union belongs on load, where its
  job is to stop a device losing a tick it made while a PUT was failing.
- **`seen` is a one-way latch**: `seen: false` is a no-op, not a reset. Its
  entire purpose is that nobody is walked through the tour twice.
- **Bounded on write** (64 ids, 64 chars each, truncated not rejected): the
  list is client-supplied and lands on the caller's own document. Small, but
  there is no reason to leave an unbounded write primitive open.

The client treats all of it as a convenience -- `pushTutorialState` is
fire-and-forget and `localStorage` stays the thing the UI reads -- so an
unreachable route costs a checkbox tick and nothing else.

**What the tests caught before it shipped**: `bson::DateTime` serialises as
`{"$date":{"$numberLong":"..."}}`, not a string. The client only tests
`seen_at` for presence, and that object is TRUTHY -- so it would have worked by
accident, typed as `string | null`, until the first person tried to display it.
`TutorialResponse` now converts to RFC 3339 like every other timestamp this API
returns. The integration test asserted the shape rather than the behaviour,
which is the only reason it failed.

### Field verification, and the defect it caught

Deployed as `v20260901-03704a315a14` (prod `0.4.43`) and checked in a real
browser against the live site:

- **8 chapters, 8 distinct illustrations**, every one loaded — `hero-mesh,
  devices, remote-desktop, private-network, tunnels, acl, rooms, calls`, 8
  distinct of 8 — and the ACL scene renders correctly in situ on the pale
  hero panel.
- `GET /auth/me` carries the new `tutorial` field; ticking a chapter wrote
  `{"done":["acl"]}` to the account.

🔑🔑 **And then the field test earned its keep.** With the account holding
`["acl"]`, a browser whose `localStorage` had been cleared showed **`0/8
done`** — on every route, not only the tutorial. `seedTutorialFromServer` had
been called from inside `AppLayout.maybeAutoOpenTour`, which returns early on
the tutorial route itself and runs at most once per app load. Neither guard has
anything to do with seeding: they exist to decide a NAVIGATION.

The seed now lives in the auth store's `adoptSession`, on the three paths where
the app learns who the caller is (`login`, `register`, `fetchMe`) — the same
shape as the existing `subscribePush()` side effect. Signing in *is* the event,
so no route or ordering can get in the way. Three store-level tests cover it,
two of which fail against the old placement.

⚠️ **Every automated check passed on the broken version** — 922 unit tests, 5
integration tests, a clean build. The composable-level test asserted the seed
FUNCTION, and nothing asserted that anything CALLS it on a real sign-in. A unit
test of a helper is not a test of the wiring.

⚠️ An SPA "reload" that only changes the hash is not a reload. The first
attempt navigated `…/tutorial#acl` → `…/tutorial#acl`, Chrome did nothing, the
in-memory state survived, and the bug looked FIXED. Force `location.reload()`.

**Re-tested on `v20260901-ee1ac3d00a2d` — PASS.** Same account, same browser,
same procedure as the failing run: clear `meshharbor:tour-progress:<uid>`, load
`/tenant/{tid}/tutorial` — deliberately the route the old code bailed on — and
the badge reads **`1/8 done`** with the key restored to `["acl"]` from the
account, against **`0/8`** and `null` before the fix. Un-ticking then wrote
`{"done":[]}` back, confirming replace-not-union against the live server too.

⚠️ **Two invalid measurements preceded that PASS, and both looked like
findings.** The first was the hash-only "reload" above. The second ran on
`/tenant/{tid}/dashboard`, which 404s: the SPA rendered `NotFoundView`, so
`auth-*.js` never loaded and the app's own `fetchMe` never ran — while
`performance` still showed one `/auth/me` request, **because that request was
the probe's own `fetch`**. Both read exactly like "the fix does not work".
🔑 On a route that does not mount the app, nothing about the app's boot
behaviour can be concluded: check WHICH chunks loaded before believing a
negative, and never count a request your own probe issued.

⚠️ The `seen_at` half is covered by unit + integration tests but deliberately
**not** field-verified: it is a one-way latch with no supported way to clear
it, and setting it on a real account for a nice-to-have measurement is not
worth an irreversible write.

⚠️⚠️ **This fix was silently REVERTED on master hours after it merged**, by an
unrelated FR-45 PR (#1144) whose branch carried the pre-fix content of all four
files. CI was green — a revert to a previously-green state always is. Re-landed
in #1147. The tell is cheap and worth running after any merge into a busy
master: `git log --oneline -- <the file you changed>` naming a PR that has no
business touching it.

## P2 as built — two deviations from this spec, both deliberate

**"forward" is dropped, not deferred.** The phase named three tours —
enroll / connect / forward — but tunnel forwards are created from the CLI and
the desktop app. There is no web surface to spotlight, so a "forward" tour
could only have pointed at a page that does not do the thing. Recorded here
rather than left as a permanently-unstarted bullet.

**Only `enroll` gets a Tutorial button.** The `viewer` tour exists and works,
but its route needs an `agentId`; an entry in the Tutorial would land a reader
on a page with nothing to point at. It starts from `?tour=viewer` once you are
on a device, and the honest follow-up is a device-row action.

### Shape, and why it is not simpler

A module-scoped step machine, ONE overlay mounted in `AppLayout`, and a
`?tour=<id>` query the Tutorial navigates with. Neither half can live where you
would first put it: the state cannot live in the starter, because the Tutorial
view is unmounted by the time the tour runs; the overlay cannot live in each
page, because a page cannot mount itself into the page it is navigating to.

🔑 **Anchors are `data-tour` attributes, never CSS shapes.** A tour selecting
`.v-btn:nth-child(2)` breaks the first time someone adds a button — and breaks
SILENTLY, highlighting the wrong control instead of failing. The e2e suite lost
hours to exactly that class of locator in the same week
(`getByText('Chat')` matching four elements; `locator('input').first()`
resolving to a hidden nav field), which is why the guard test asserts every
anchor still EXISTS in the source: a renamed anchor otherwise just makes the
overlay flicker and skip a step, and nothing anywhere fails.

⚠️ Three behaviours worth keeping: the dimming is four plain divs rather than an
SVG mask (a mask can be clipped by a stacking context; the highlighted control
also stays interactive), a step whose anchor never renders advances after 1.5 s
rather than stranding the reader on a dimmed page, and the query param is
stripped on arrival so a refresh or a shared link cannot replay the tour.

## Acceptance criteria

- [ ] A brand-new user's first login lands on the Tutorial once, never twice;
      dismiss works instantly
- [ ] Every chapter renders its hero + steps; every step's deep link lands on
      the real page/dialog with the right tenant id
- [ ] The `?` app-bar icon and user-menu entry open the Tutorial for an
      onboarded user at any time
- [ ] Empty states on /devices and the rooms list link to their chapters
- [ ] `bun run test:unit` + `bun run build` green; no new runtime deps in P1

## Open decisions

1. Should the auto-open ALSO trigger for a user invited into an established
   org (org not fresh, user new)? Leaning yes-with-flag (same localStorage
   key — it is per-user).
2. Chapter for the desktop companion / setup wizard (installers) — or keep
   install coverage inside the Devices chapter's enroll step? Leaning inside.

## Out of scope

Marketing-site tours; per-plan gating (the tutorial shows everything and
labels plan-gated features as such); localization beyond the existing en.json.

## Field-verification log

- **2026-08-27, prod (`v20260827-cb368eefea67`) — P1 live.** `/tenant/{tid}/tutorial`
  serves 200 through the SPA fallback; the route's own lazy chunk
  (`TutorialView-*.js`) is referenced from the entry bundle, and all four
  hero SVGs return 200 at their built sizes (10.2–12.6 KB), i.e. the
  README artwork really ships rather than 404-ing behind a broken import.
  Chapter deep links are contract-tested against the route table, so a
  renamed route fails the build rather than dead-ending a reader.
  Remaining for closure: an operator read-through of the eight chapters
  (prose/accuracy), and one fresh-org account to watch the auto-open fire
  exactly once — both need a human, not a probe.
