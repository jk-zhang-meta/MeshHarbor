# FR-82: A permission refusal is not a logout, and a managed role is not frozen at its birthday

**Issue:** [#1540](https://github.com/gjovanov/roomler-ai/issues/1540) · **Status:** **shipped + field-verified 2026-09-09** (`865a261c2`, image `hosted-20260909-786f016`) — **all 10 criteria met; AC8 closed by the operator from the reporting seat on 2026-09-09** ·
**Field report:** a GROX member opened `/tenant/69a1dbba…/devices`, got a 403 and
was signed out of the product.

## Goal

Two independent defects, one visible symptom. Both are *classes*, and both are
closed structurally rather than instance-by-instance:

1. **The SPA treated every `403` on a `GET` as a dead session** — it cleared the
   sign-in hint and pushed to `/login`. A 403 is an authorization verdict on a
   credential the server just *accepted*; it is the opposite of a 401. Under
   that rule, every permission-gated read anywhere in the product was a logout
   waiting for the first caller who lacked the bit.
2. **A system-managed role's permission mask was written once, at tenant
   creation, and never again.** Adding a permission bit therefore reached only
   organisations created *afterwards*. Measured on the hosted deployment: **63
   of 72 orgs** still carried `admin = 0x7ffff7` — no `MANAGE_AGENTS`, no
   `REMOTE_CONTROL`, neither audit view — every fleet feature shipped since
   those orgs were created, invisible to their own admins.

## The field event, end to end

The reporting member holds `member` (`0x3cf81`) + a hand-made **`Remote
Operator`** role (`0x3000000` = `MANAGE_AGENTS | REMOTE_CONTROL`) in GROX.
That custom role is itself evidence of defect 2 — the operator built it by hand
because the org's own seeded `admin` role could not see the fleet.

```
mask 0x303cf81
  ├─ MANAGE_AGENTS  ⇒ canSeeFleetNav() true  ⇒ the "Devices" nav item renders
  └─ MANAGE_TENANT  ABSENT
                     │
/tenant/{id}/devices ┤
  ├─ GET /device                    membership-gated   200
  ├─ GET /agent                     membership-gated   200
  ├─ GET /member                    membership-gated   200
  ├─ GET /overlay-node              membership-gated   200
  ├─ GET /tunnel-client             membership-gated   200
  └─ GET /ephemeral-key-settings    MANAGE_TENANT      403  ← EnrollKeysSection, on mount
                                                        │
                              api/client.ts: 403 + GET ⇒ clearSignedIn() + push('/login')
```

Enumerated on the LIVE page rather than read off the source, by loading it in
a browser and reading the network log — the devices page fires **12
tenant-scoped requests**, and `ephemeral-key-settings` is the only one that
needs anything beyond membership:

```
agent?per_page=100 · device?page=1… · agent · member · overlay-node ·
tunnel-client?per_page=100 · member/me · room ×2 · message/unread-count ×5
    ⇒ membership-gated, 200 for any member
ephemeral-key-settings
    ⇒ MANAGE_TENANT, 403 for everyone but the owner
```

One request, one bug, and nothing else on that page waiting to do it again.
(All 200 in the capture because it ran as the OWNER — which is the same reason
the defect went unreported for a week.)

`DevicesView.vue` mounts `<enroll-keys-section>` unconditionally; the card
"fetches the switch itself and stays empty otherwise" (FR-51 P4, #1148,
2026-09-01). The store's `catch` — commented *"left `null` on a 403 — 'not an
admin' is not 'disabled'"* — is correct and was never reached on the branch
that mattered: **the logout fired one layer below it, inside `request()`,
before the throw the store was waiting to catch.**

⚠️ **The owner is the only member of any org this did not hit.** `MANAGE_TENANT`
is deliberately absent from `DEFAULT_ADMIN`, so an org's own *admins* were
logged out by opening their Devices page too. Only the owner survived, via the
`ADMINISTRATOR` bypass — which is why it went unreported for a week.

### Why nothing caught it

`ui/src/__tests__/api/client.spec.ts` asserted the logout as **correct
behaviour**, with a comment explaining the case it existed for. And three
predicates in `utils/permissions.ts` (`canQueryAnalytics`, `canManageInvites`,
`canViewExecAudit`/`canViewSshAudit`) are fail-closed *specifically to route
around this rule* — each written after the same bug surfaced in a different
corner. The codebase had been paying for the rule in instances for months
without anyone pricing the rule itself.

## Key design

### 1. A 403 never ends a session (`ui/src/api/client.ts`)

| body `error` | client does | rationale |
|---|---|---|
| `not_a_member` | leave the **tenant** — `push({name:'dashboard'})`, session intact | You are not in this org. You are still in your others. |
| anything else, **including absent** | throw, nothing more | It is an answer. The caller already handles it. |

⚠️ **The default direction is the whole guarantee.** An *unclassified* 403 does
nothing but throw, so a newly-added permission-gated route is inert here by
construction — not "safe until somebody remembers to add a predicate for it".

⚠️ The verdict comes from the **server**, not a message-string sniff on the
client: `chat`'s `Forbidden("Not a member of this room")` is a 403 of exactly
the same shape, and evicting someone from their organisation over a private
channel would be absurd.

### 2. `not_a_member` is a machine-readable code, not prose

`ApiError::NotAMember` (`crates/core/src/error.rs`) ⇒ `403 {"error":
"not_a_member"}`; `DaoError::NotAMember` carries it up from
`TenantDao::get_member_permissions`. The 40 `ApiError::Forbidden("Not a
member".to_string())` call sites across the api crate and all six modules
become the variant; the one room-scoped refusal deliberately does not.

### 3. `MANAGED_ROLES` — one table, seeded from and reconciled to

`crates/db/src/models/role.rs`. Before it there were **two** divergent copies:
`TenantDao::create_default_roles` (which ran) and `RoleDao::seed_defaults`
(dead — Titlecased names, no `guest`, and a `Moderator` carrying
`MANAGE_MEETINGS` and *not* `REMOTE_CONTROL`, the reverse of the live one). The
dead copy is deleted; tenant creation and the reconcile now read the same rows.

`TenantDao::reconcile_managed_roles()` runs at startup under the **existing
`startup_maintenance` lease**, so exactly one pod does it per window.

⚠️ **Additive: `new = stored | definition`, never a replace.** A managed role's
mask *is* editable (`PUT …/role/{id}`; only *deletion* is refused), so an org
may legitimately have added a bit. Overwriting would silently revoke that;
OR-ing cannot. **The cost, stated so nobody rediscovers it: a bit REMOVED from
a definition — a tightening — does not propagate**, and needs its own migration
that says out loud whose permissions it takes away.

⚠️ **The mirror case is the surprising one: a bit an ORG removed comes back.**
One stored mask cannot distinguish *"never had it"* from *"took it away on
purpose"*, so an org that narrowed a managed role sees it silently widened at
the next boot. Accepted deliberately — the alternative (replace) silently
revokes instead, and revoking is the worse failure — but it means **narrowing a
managed role is not a supported way to restrict a team**: a custom role is, and
the aggregation's `is_managed: true` match never sees one.

⚠️ Grouped by `(name, permissions)`, one `update_many` per group — 12 writes
for the whole deployment, not 360. Matching the exact stored value also makes
it idempotent and safe against a concurrent editor: a role changed underneath
falls out of its group's filter instead of being clobbered.

⚠️ A managed row whose name is not in the table is **reported and left alone**.
Visible drift beats drift corrected by guesswork.

### 4. The grant leaves a row, not just a log line

`role_reconcile_audit`, written from inside `reconcile_managed_roles` one
statement after the `update_many` it describes — so the receipt and the write
share `stored`/`reconciled` directly and cannot drift. One row per **changed**
stratum: role, rows covered, `stored` → `granted`, the `gained` mask, and the
permission **names** it added.

⚠️ **Not tenant-scoped**, unlike every other audit collection here
(`config_audit`, `ssh_audit`, `exec_audit`, …). Those record a request by a
user against a device. This records a deployment-wide migration with no tenant,
no device and no requester; one row covers every organisation that shared a
stale mask, which is exactly the grouping the write used.

⚠️ **Not TTL-indexed**, also unlike the others — the one deliberate deviation
from the 90-day convention. Those bound an append-only stream of routine
decisions. This is bounded already: one row per changed stratum, only on the
boot that changes anything, so a deployment's entire history is ~12 rows and
then nothing forever. A TTL would delete the only record of an irreversible
grant and re-create this very gap, just more slowly.

⚠️ **Best-effort**, like `config_audit`: a failed insert is logged and the
reconcile continues. The roles are already correct by then, and refusing to
finish a migration because its receipt could not be filed trades a real outage
for a bookkeeping one.

⚠️ It carries no index and no `index_plan` entry **on purpose** — a collection
of ~12 rows needs none, and adding one would re-record the composition baseline
for no query it would ever serve.

### The measured drift

| role | stored | → target | gains | orgs |
|---|---|---|---|---|
| `owner` | `0xffffff` | `0x7fffffff` | `0x7f000000` | 63 |
| `owner` | `0x1fffffff` / `0x7ffffff` | `0x7fffffff` | — | 1 + 1 |
| `admin` | `0x7ffff7` | `0x577ffff7` | `0x57000000` | 63 |
| `admin` | `0x77ffff7` / `0x177ffff7` | `0x577ffff7` | — | 1 + 1 |
| `moderator` | `0x7ef91` | `0x207ef91` | `REMOTE_CONTROL` | 63 |
| `member` | `0x3cf81` | unchanged | none | 72 |
| `guest` | `0x801` | unchanged | none | 72 |

Each distinct `owner` mask is a snapshot of `permissions::ALL` on the day that
org was created — the freeze, visible in the data.

⚠️ `owner` gaining `0x7f000000` is a **no-op in effect**: the row already
carries `ADMINISTRATOR` and passes `has()` by the bypass. It is reconciled so
the stored mask stops lying, not to change an outcome.

⚠️ **`EXEC_DEVICE` and `SSH_DEVICE` are in no row below the `ADMINISTRATOR`
bypass.** The reconcile grants whatever the table says to every existing org,
so `DEFAULT_ADMIN |= EXEC_DEVICE` — a one-token edit that reads as tidying —
would open exec-as-SYSTEM on the whole deployment at the next boot, with no
migration to review and no admin action to audit.
`no_managed_role_below_administrator_seeds_a_root_shell` makes that
unrepresentable. (`owner` holds both as part of `ALL`, where the bypass already
answered true for every bit — the test skips a row carrying it, because failing
there would be failing for a reason unrelated to the risk. The first draft of
the test did not, and said so on the first run.)

### 4. The org switches are not asked for without the bit

The three `MANAGE_TENANT` GETs (`exec-settings`, `ssh-settings`,
`ephemeral-key-settings`) are gated **in the store**, not per call site — the
rule FR-75 (#1447) paid for on the `network` routes. After (1) a 403 there is
harmless; this is about not spending a round-trip on a refusal known in advance,
and not filling the browser console and server log with 403s that make the real
ones harder to see.

⚠️ It **awaits** `ensureMyMembership` rather than reading `myPermissions`:
AppLayout's `/member/me` is in flight while the page mounts, so a synchronous
read is a coin-flip between "hidden from the owner" and "fires anyway".

## Phases

| # | phase | kill switch | status |
|---|---|---|---|
| 1 | `not_a_member` on the wire; 40 call sites; the client stops logging out | none — reverting is a one-line revert of the 403 branch, and the old behaviour is the defect | built 2026-09-08 |
| 2 | `MANAGED_ROLES` as the one table; dead `seed_defaults` deleted | none — pure de-duplication, byte-identical seed output | built 2026-09-08 |
| 3 | `reconcile_managed_roles` under the startup lease | `MESHHARBOR__AUTH__RECONCILE_MANAGED_ROLES=false` (default on; warns at boot when off) | built 2026-09-08 |
| 4 | store-level `MANAGE_TENANT` gate on the three org switches | none needed — after phase 1 the ungated 403 is harmless, so the worst case of a wrong gate is a hidden card, not a logout | built 2026-09-08 |
| 5 | docs updated with diagrams, linked from `docs/README.md` | — | `docs/permissions.md`, 2026-09-08 |

## Acceptance criteria

- [x] **AC1** A permission 403 on a GET leaves the session intact — locked by a
      unit test that replaces the one asserting the opposite.
      *`ui/src/__tests__/api/client.spec.ts`: "a permission 403 on a GET does NOT
      end the session". The test it replaces asserted the logout as correct,
      which is why nothing caught this for as long as it stood.*
- [x] **AC2** An *unclassified* 403 neither logs out nor navigates.
      *Same file: "an UNCLASSIFIED 403 neither logs out nor navigates" — the
      default direction is the guarantee, so a newly-gated route is inert on the
      client by construction.*
- [x] **AC3** A `not_a_member` 403 leaves the tenant and keeps the session.
      *Same file: "a not_a_member 403 leaves the tenant and KEEPS the session".*
- [x] **AC4** A non-member's tenant-scoped GET answers `error: "not_a_member"`;
      a member-without-the-bit answers `error: "forbidden"` naming it.
      *`role_reconcile_tests::{a_non_member_is_refused_as_not_a_member,
      a_member_without_the_bit_is_refused_as_forbidden_naming_the_permission,
      a_membership_gated_read_tells_a_non_member_apart_from_a_member}` — all
      three ran `ok` in the green integration lane (run 34321311457, the lane
      that needs real MongoDB + Redis), not merely present in the tree.*
- [x] **AC5** `reconcile_managed_roles` raises a stale mask to its definition,
      **preserves a bit an org added itself**, and is a no-op on a second run.
      *`role_reconcile_tests::{the_reconcile_raises_a_stale_mask_and_keeps_what_the_org_added,
      the_reconcile_is_a_no_op_on_a_second_run,
      the_reconcile_leaves_a_role_it_does_not_define_alone}`, same run.*
      ⚠️ The **preservation** half is test-proven only, and cannot be otherwise
      here: after the reconcile every managed role on prod collapsed to exactly
      one mask, so no organisation carries a bit of its own for the additive
      path to keep. A production that cannot exhibit the case cannot prove it.
- [x] **AC6** No managed role below the `ADMINISTRATOR` bypass seeds
      `EXEC_DEVICE` or `SSH_DEVICE`.
      *`crates/db/src/models/role.rs::no_managed_role_below_administrator_seeds_a_root_shell`,
      re-run locally 2026-09-09 (8 passed). This is the guard that makes
      `DEFAULT_ADMIN |= EXEC_DEVICE` — a one-token edit that reads as tidying —
      fail the suite instead of opening exec-as-SYSTEM fleet-wide at the next
      boot, because the reconcile grants what the table says to EVERY org.*
- [x] **AC7** The three org-switch GETs are not fired without `MANAGE_TENANT`,
      and the flag stays `null` (unknown) rather than `false`.
      *`ui/src/__tests__/stores/agents.spec.ts`: "an unknown mask blocks the org
      switches rather than guessing".*
- [x] **AC8** Field: the reporting member opens the GROX Devices page, the grid
      renders, and the session survives. *Done by the operator on
      `hosted-20260909-786f016`, from the reporting seat itself — the account's
      effective mask in GROX reads `0x303cf81` (`member 0x3cf81` + the
      hand-made `Remote Operator 0x3000000`), it is **not** the tenant owner,
      and bits 3 (`MANAGE_TENANT`) and 23 (`ADMINISTRATOR`) are both **clear**
      — so it is the one seat that could falsify this, and the page rendered
      with the session intact. Verified against prod Mongo rather than assumed;
      the before-run is the original field report, same account, same page.*
      ⚠️⚠️ **It passes through AC7's gate, not AC1's branch, and that is not
      what the criterion's wording implies.** `fetchOrgEphemeralKeysEnabled`
      now short-circuits on `mayReadOrgSettings` (`ui/src/stores/agents.ts`),
      so from a seat without `MANAGE_TENANT` the `ephemeral-key-settings` GET
      **is never fired** — the 403 that used to end the session no longer
      happens on that page at all. Two independent fixes shipped together and
      the field test only exercises the outer one; the symptom is genuinely
      gone, but see the note under §The client half for what stays unproven.
- [x] **AC9** Field: prod logs show the reconcile's arithmetic once, and a
      second pod restart reports "already match their definitions".
      *Verified twice, independently — the arithmetic read live from the leader
      pod, and the outcome re-measured from Mongo against a before-state taken
      on the previous image (log below). ⚠️ The two halves did NOT come from
      the same place, and could not have: see the log's last row.*
- [x] **AC10** Docs updated/created with diagrams, linked from `docs/README.md`.
      *`docs/permissions.md` (7 sections, 3 mermaid diagrams: the bit catalogue,
      the reconcile's additive merge, and what each refusal means), with its row
      in `docs/README.md`'s reference table.*
- [x] **AC11** The grant leaves a durable record: one `role_reconcile_audit`
      row per changed stratum with its arithmetic and the permission names,
      and an idempotent run writes none.
      *`the_grant_leaves_a_record_that_outlives_the_pod_that_made_it`, which
      also asserts no row ever names `EXEC_DEVICE`/`SSH_DEVICE` — the table's
      guard covers the definition, this covers what the migration handed out.
      Added after the roll, because the INFO line the FR shipped with was gone
      from every surviving pod ten minutes later.*

## Open decisions

- **Should `MANAGE_TENANT` join `DEFAULT_ADMIN`?** Left alone deliberately —
  configuring the organisation is the owner's job, and that is a policy call,
  not a bug. The consequence, now visible rather than fatal: an org's admins do
  not see the Devices page's enrollment-keys card. Revisit if operators ask.
- **A bit removed from a definition** does not propagate (see §3). No mechanism
  proposed until there is a real tightening to carry.
- ~~**The grant's only record is a log line with a pod's lifetime.**~~
  **RESOLVED — see §4.** Measured after the fact: ~10 minutes post-roll the
  seven `managed role reconciled` lines were gone from both surviving pods,
  because `kubectl logs` holds only the current container and the emitting pod
  had been replaced. The reconcile is one-shot per deployment and
  self-evidencing in the data *if* someone captured a before-state — but nobody
  has to, and next time nobody may.

  ⚠️ **This entry first proposed "an `audit_logs` row (the collection, its
  90-day TTL and the writer all already exist)". That was wrong, and wrong in
  this FR's own signature way** — `audit_logs` is named in `CLAUDE.md`'s
  collection list and in a comment in `ephemeral.rs` (*"the P4 surface adds it
  to `audit_logs`"*), and there is **no such model, collection, index or
  writer** anywhere in the tree. It was reasoned from a doc line instead of
  checked, which is precisely the *"a false invariant in a comment is what the
  next reader reasons from"* failure this FR was written about. §4 builds the
  collection instead of assuming it.

## Out of scope

- `token_epoch` / session revocation (the open MEDIUM in `CLAUDE.md`): a stolen
  access token is still valid for 7 days. Unrelated to this arc, and a 401
  concern rather than a 403 one.
- The permission-bit ceiling (bit 52; `ui/src/utils/permissions.ts` does its
  mask arithmetic without bitwise operators for that reason).

## Field-verification log

| Date | What | Result |
|---|---|---|
| 2026-09-09 | **BEFORE**, measured on prod Mongo (`roomler2.roles`) while the *previous* image was still serving — so the pass below means something | 72 tenants · 360 managed rows · **12 drift strata**: `admin 0x7ffff7 ×63`, `owner 0xffffff ×63`, `moderator 0x07ef91 ×63`, plus 6 singleton/small strata. The defect reproduced exactly as surveyed |
| 2026-09-09 | Pre-flight, with a **positive control** (an absent key and a broken `kubectl` look identical) | control `MESHHARBOR__APP__ENVIRONMENT` → `production`; `RUST_LOG` **absent** ⇒ the compiled `EnvFilter` default applies ⇒ `meshharbor_api=debug` ⇒ the reconcile's INFO lines can actually reach the log; `MESHHARBOR__AUTH__RECONCILE_MANAGED_ROLES` **absent** ⇒ defaults on |
| 2026-09-09 07:35 | Promoted `hosted-20260909-786f016` (from `865a261c2`) | both pods on it, `/health` 200 |
| 2026-09-09 07:37 | **The arithmetic**, read live from the leader pod | 7 `managed role reconciled to its definition` lines; `admin rows=63 stored=0x7ffff7 gained=0x57000000` ⇒ `MANAGE_AGENTS, REMOTE_CONTROL, VIEW_REMOTE_AUDIT, VIEW_EXEC_AUDIT, VIEW_SSH_AUDIT`. The other pod: `lease held elsewhere` — the leader gate held |
| 2026-09-09 | **AFTER**, re-measured from Mongo against the before-state | **12 strata → 5**, every managed role at all 72 orgs: `owner 0x7fffffff`, `admin 0x577ffff7`, `moderator 0x207ef91`, `member 0x3cf81`, `guest 0x801` |
| 2026-09-09 | **AC6 in the field, not just in a unit test** | the granted mask `0x57000000` is bits 24,25,26,28,30 — **bits 27 (`EXEC_DEVICE`) and 29 (`SSH_DEVICE`) are CLEAR**. The one-shot grant across 63 orgs handed out the audit/agent bits and no root shell |
| 2026-09-09 | The additive rule, on a real custom role | GROX's hand-made `Remote Operator` **untouched at `0x3000000`** — it is not `is_managed`, so it never enters the aggregation |
| 2026-09-09 | Idempotence | a later leader logged `managed roles already match their definitions groups=5`. ⚠️ A restart is **not** automatically a second run: the first replacement booted inside the previous leader's 120 s lease and correctly skipped |
| 2026-09-09 | ⚠️⚠️ **The arithmetic no longer exists anywhere** — searched both surviving pods' full logs ~10 min later: zero `managed role reconciled` lines, only the one `already match` | The code's own comment asks for it to be *"readable in `kubectl logs` afterwards"* because this **grants permissions across every tenant**. `kubectl logs` holds only the current container, so the sole record of a one-way, fleet-wide grant has a pod's lifetime. It survived here only because someone was watching live and because a before-state had been captured. See "Open decisions" |

| 2026-09-09 | **AC8 — the reporting member, on the shipped build** | `goran.jovanov@roomler.ai` opened `/tenant/69a1dbba…/devices`: the grid rendered and the session survived |
| 2026-09-09 | ⚠️ **AC8's negative control**, checked BEFORE believing the pass | not the tenant owner; effective mask `0x303cf81` = `member 0x3cf81` + custom `Remote Operator 0x3000000`; `MANAGE_TENANT` **absent**, `ADMINISTRATOR` **absent** — so it is a seat that could falsify the criterion, unlike the owner's. (A pass from a seat holding either bit would have proved nothing, which is exactly how this defect survived a week.) |
| 2026-09-09 | ⚠️⚠️ **Correction to the row above, and to what I first said about it** | I wrote that "the 403 still happened and the old rule would still have fired". **It did not.** AC7's store-level gate (`fetchOrgEphemeralKeysEnabled` short-circuits on `mayReadOrgSettings`) means that seat never fires the request at all, so the pass exercises AC7's gate rather than AC1's branch. The symptom is genuinely gone; the `forbidden` flavour of the 403 branch stays field-unproven, and only the unit tests cover it. Two fixes shipped together and the field test reaches the outer one — a real limit on what AC8 establishes, not a quibble |

~~⚠️ **AC8 is still owed and the issue was closed without it.**~~ **Done
2026-09-09, above.** It needed a member who lacks `MANAGE_TENANT`; the owner is
the one member of any org the defect never hit, so the owner could not verify
it. GROX has **8 non-owner members** on `member` (`0x3cf81`), and the seat used
was the reporting one.

⚠️ The reconcile does **not** make AC8 pass — `MANAGE_TENANT` stays out of
`DEFAULT_ADMIN` deliberately. ⚠️⚠️ Nor does AC1's branch, which is the part
worth reading twice: **AC7's gate means the request is never fired**, so from
that seat there is no 403 to mishandle. The page works, and the reason it works
is the fix one layer out from the one AC8's wording implies.

### The client half — the 403 that no longer ends a session

The log above is entirely about defect 2. Defect 1 lives in the **bundle**, so
nothing about it is verifiable until prod serves the new one; it was measured
the same way, before and after.

| read | result |
|---|---|
| **BEFORE** — the bundle prod was serving, `index-CWf4GqhQ.js` | exactly **one** `status===403` site, and it was the defect: `.status===403&&n==="GET"&&!Tr.some(c=>e.startsWith(c))&&Or()` — method-gated, unconditional logout |
| **AFTER** — `index-CxPcVy01.js` | still one site, now `o.status===403&&!Tr.some(…)&&i?.error==="not_a_member"&&Gl()`: the method test gone, the logout gone, the navigation conditioned on the server's own code |
| the server's half, by raw `fetch` from the signed-in SPA (deliberately bypassing the interceptor) | a non-member tenant GET answers **403 `{"error":"not_a_member"}`** on both `/room` and `/agent` — the machine-readable code `ApiError::NotAMember` was added for, not a message string |
| the page shape that produced the report | navigating to a **non-member org's Devices page** landed on `/`, **not** `/login`; the dashboard rendered with its org list, and an authenticated GET on the caller's own tenant answered **200 with 21 agents** immediately after — the session was never touched |
| **AC8**, by the operator — the reporting seat itself, on the GROX Devices page | the page rendered and the session survived. The seat was verified against prod Mongo, not assumed: effective mask `0x303cf81` (`member` + the hand-made `Remote Operator`), **not** the tenant owner, bits 3 (`MANAGE_TENANT`) and 23 (`ADMINISTRATOR`) both clear — the one seat that could have falsified it. The before-run is the original report: same account, same page, signed out |

⚠️ This proves the `not_a_member` arm end to end and the *absence* of the old
expression from the shipped bytes.

⚠️⚠️ **The `forbidden` arm is still not exercised in the field, and after this
fix it cannot be from the page that reported it.** AC8 passed — the operator
opened the Devices page from the reporting seat (`0x303cf81`, not the owner,
bits 3 and 23 clear) and the page rendered with the session intact — but it
passed through **AC7's store gate**: `fetchOrgEphemeralKeysEnabled` now
short-circuits on `mayReadOrgSettings`, so that seat never fires the
`ephemeral-key-settings` GET and the 403 never reaches the interceptor. Both
fixes are real and the symptom is gone; the point is that the field pass
attributes to the outer one. What carries the inner one is the unit tests
(AC1–AC3), the shipped bytes above, and the `not_a_member` navigation — **not**
a field observation. A future reader must not cite AC8 as evidence that a
`forbidden` 403 no longer ends a session.

⚠️ Defence in depth is the right outcome here, but it has a cost worth naming:
with the store gate in front of it, a regression in `client.ts` alone would be
invisible from this page. The unit tests are the only thing standing under that
branch now.

⚠️ Worth keeping about the prediction that gated this roll: §The measured drift
was written from production *before* the merge, and `DEFAULT_ADMIN =
0x577ffff7` has bits 27 (`EXEC_DEVICE`) and 29 (`SSH_DEVICE`) clear — so the
63-org group's move was **falsifiable**, and anything other than a gain of
`0x57000000` would have been exec-as-SYSTEM spreading across 63 organisations
at one boot. A prediction that could not have failed would have proved nothing.

## AC11 in production — deployed 2026-09-10, and what it cannot show

`hosted-20260910-dc54fc9` (master `60e427218`, version `0.4.97`) promoted and
rolled; both pods ready, `/health` 200 with all six modules, 17 fleet peers back
on the overlay after the WS cycle, and the shipped bundle still carries the
fixed 403 rule (`status===403 && …==="GET"` → **0 occurrences**,
`not_a_member` branch present).

| | before the roll | after |
|---|---|---|
| image | `hosted-20260909-786f016` | `hosted-20260910-dc54fc9` |
| `role_reconcile_audit` | **does not exist** | **does not exist** |
| managed-role strata | 5, all 72 orgs | 5, all 72 orgs |
| leader pod | — | `managed roles already match their definitions groups=5` |
| other pod | — | `Startup maintenance lease held elsewhere` |

⚠️⚠️ **The zero rows are the predicted result, and they are also the limit of
this test.** The deployment had already converged on 2026-09-09, so there was
nothing for the reconcile to grant and therefore nothing to record — the
collection is not merely empty, it does not exist, because Mongo creates
lazily on first insert. So this roll proves the code is live, the leader gate
holds and the idempotent path is quiet; it proves **nothing about the writer**.

That is the same shape as AC8's caveat above, and it is stated for the same
reason: a reader seeing AC11 ticked should not infer it was field-exercised the
way AC9 was. The writer's evidence is
`the_grant_leaves_a_record_that_outlives_the_pod_that_made_it`, which runs
against real MongoDB in the integration lane. Its **field** exercise is
deferred, by design, to the next boot after a bit is added to `MANAGED_ROLES` —
and manufacturing a permission grant across 72 production organisations to test
the audit of permission grants would cost more than the evidence is worth.

🔑 Two acceptance criteria in one FR now carry "green, but through a different
path than the wording implies". Neither was caught by the test that produced
the green; both were caught by asking *which layer actually made this pass*.
