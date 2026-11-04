# FR-11 — Server-side grids: members / files / invites, devices default sort, mesh display names

> **CLOSED 2026-08-27** — issue #784 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#784](https://github.com/jk-zhang-meta/MeshHarbor/issues/784)
**Status:** implementation in progress (P1 backend → P2 UI)

## Goal

Extend the devices-grid treatment (server-side pagination + search + sort,
horizontal scroll, per-user columns — shipped 2026-08-26) to the remaining
list pages, plus two follow-ups from operator review:

1. **/devices** sorts by **online-then-name by default** (today: name).
2. The dashboard **mesh chart labels prefer `display_name`** over the device
   name.
3. **/admin/members**: shows **email**, supports **add / remove members
   directly by email (no invite)**, server-paginated grid searchable by name
   AND email, sortable, h-scroll.
4. **/files**: server-paginated grid, name-searchable, sortable, h-scroll.
5. **/invites**: same grid treatment (today: an unpaginated
   `v-data-table-virtual` silently showing only the first 25).

## Key design (anchors verified against master @ `1b25e3d8`)

### 1. Devices default sort — `crates/api/src/routes/device.rs`
`sort_key` resolves `unwrap_or("name")` at `:113`, so the handler cannot
distinguish "default" from explicit `sort=name`. Change: keep the param as
`Option`; `None` → a compound `(presence_rank, effective_name)` ordering
(the sidebar's exact order); `Some(k)` → the existing whitelist (`:114-129`)
unchanged. `cmp_rows` (`:377-401`) gains the compound arm; the id tiebreak
(`:219-223`) stays. UI needs **zero change**: an untouched grid emits
`sortBy: []` → no `sort` param (`AgentsSection.vue:1486-1496`,
`stores/devices.ts:77-78`). `device_list_tests.rs:280`'s comment updates
(order itself survives — the three fixture agents share one presence bucket).

### 2. Mesh names — server-side, deliberately
`tenant_mesh` (`crates/api/src/routes/stats.rs:737`) projects agents at
`:786-789` **without `display_name`** — add it; prefer it in the dashboard's
`meshNodes` computed (`TenantDashboard.vue:298`:
`agent?.display_name || agent?.name || n.name || …`) + the optional field on
`MeshPayload.agents[]` (`stores/stats.ts:85`). Client-side joining via
agentStore would be wrong twice: the mesh panel is member-visible while
`fetchAgents` is fleet-gated, and the mesh polls 60s while agents fetch once.
Tunnel-client nodes keep their MagicDNS label (no third aggregation — open
decision).

### 3. Members — `routes/user.rs` + `routes/invite.rs` + `dao/tenant.rs`
- **List** (`user.rs:43-94`): becomes the devices-style in-memory compose
  (members per tenant are tens): fetch the tenant's members + batch the user
  rows (display_name/username/**email** — widen the projection beside
  `dao/user.rs:362-395`), filter `q` over name+username+email, sort whitelist
  `name | email | joined_at` (default joined_at asc, as today), slice,
  envelope. Flat `MemberListQuery` — never `#[serde(flatten)]`
  (`device.rs:30-34` postmortem). `MemberResponse` (`user.rs:11-21`) gains
  `email`.
- **Add by email, no invite**: `AddMemberRequest` (`invite.rs:73-78`) gains
  `email: Option<String>` (exactly one of user_id/email); resolved via
  `users.find_by_email` (`dao/user.rs:87-92` — the address is a *proven
  reservation*, so adding by it is adding a verified account). Unknown
  address → 404 with "no account with that address — use Invites". Gate
  unchanged: `INVITE_MEMBERS` + `check_grant_roles` (`invite.rs:441`).
- **Remove** (NEW — no route exists today, verified): `DELETE
  /tenant/{tid}/member/{user_id}` on the member router (`lib.rs:167-172`),
  gated on **`KICK_MEMBERS`** (`role.rs:35` — defined, never consumed until
  now). Refusals: the tenant **owner** cannot be removed (409); self-removal
  is allowed (it is "leave"). New `TenantDao::remove_member` =
  `members.hard_delete` (`TenantMember` has no `deleted_at`; `base.rs:341`).
  Room-membership rows are left in place — tenant `is_member` is the access
  gate everywhere, so a removed user loses access structurally; cascade is a
  noted follow-up.

### 4. Files — `routes/file.rs` + `dao/file.rs`
Both list routes already take `PaginationParams` (`:50`, `:79`). Add optional
flat `q`/`sort`/`dir`: DAO (`dao/file.rs:67-120`) grows a `q` (`escape_regex`
`$or` over `filename`/`display_name`, `$options:"i"`) and a sort whitelist
(`filename | size | created_at`, default `created_at:-1` — absent params ⇒
today's behavior byte-for-byte).

### 5. Invites — `routes/invite.rs` + `dao/invite.rs`
`list_invites` (`:221-241`) already paginates; add flat `q` (escaped `$or`
over `code`/`target_email`) + optional `status` exact filter to
`list_by_tenant` (`dao/invite.rs:73-85`). UI: `InviteManageView.vue`'s
`v-data-table-virtual` (`:25-29`, headers `:151-158`) becomes a
`v-data-table-server` with the devices toolbar pattern; the store
(`invite.ts:99-114`) drives page/per_page/q and exposes the envelope.

### P2 UI (all three pages)
The devices-grid kit verbatim: `v-data-table-server` + `@update:options` as
the single fetch trigger (`AgentsSection.vue:1483-1496`), 300ms debounced
search with page-1 reset (`:1468-1477`), h-scroll CSS (nowrap +
`width:max-content` wrapper), `useGridColumns` +
`GridColumnPickerDialog` (`composables/useGridColumns.ts:34-163`,
`components/common/GridColumnPickerDialog.vue`) with grid ids
`members` / `files` / `invites`. Members additionally: Add-member dialog
(email + role select) and a per-row Remove with confirm.

## Phases / status

| Phase | Content | Kill switch | Status |
|-------|---------|-------------|--------|
| P1 | Backend: device default sort, mesh display_name, member list compose + email + add-by-email + remove, files q/sort, invites q/status | every new param optional — absent ⇒ prior behavior; remove/add-by-email are new routes | in progress |
| P2 | UI: three grids on the devices kit + mesh label line | per-page UI; no server coupling beyond P1 | planned |

## Acceptance criteria

- [ ] /devices with no explicit sort lists online devices first, name-ordered
      within each presence bucket; explicit header sorts unchanged
- [ ] Mesh chart shows display names when set (member-visible, live within a
      poll cycle of a rename)
- [ ] Members grid: email column; search hits name AND email; sortable;
      paginated; h-scroll
- [ ] Add member by email: verified account added instantly with role;
      unknown address → clear 404 message; escalation guard intact
      (cannot grant roles you don't hold)
- [ ] Remove member: gated KICK_MEMBERS; owner cannot be removed; removed
      user loses tenant access on next request
- [ ] Files + invites grids: paginated/searchable/sortable, h-scroll; the
      invites page no longer silently caps at 25
- [ ] All list endpoints byte-compatible with parameterless requests
- [ ] Integration tests per endpoint (search/sort/pagination/authz);
      vitest for the new store params + grids

## Open decisions

1. Mesh labels for tunnel-client nodes (needs a third aggregation) — later?
2. Cascade room_members on member removal — follow-up?

## Out of scope

Room-files view restructure (the room-scoped list gets the same params but
its chat-panel UI stays); member ban/mute (BAN_MEMBERS stays unconsumed).

## Field-verification log

- **2026-08-27, prod (`v20260827-e175b50dd9a8`) — ALL PASS, #784 closed.**
  Devices default sort: 32 rows, 15 online first, presence buckets strictly
  ordered, names ascending within buckets, head = `corp-laptop-1` (a
  display_name — effective-name sorting proven). Members: 9 rows all with
  email, `sort=email` ordered, `q=goran` → 5. Add-by-email: unknown → 404,
  both-fields → 400; full net-zero cycle on the throwaway verified test
  account (201 → visible in grid → DELETE 200 → second DELETE 404).
  Files: 16 rows, `sort=size desc` ordered, unknown sort → 400. Invites:
  `status=active` (9) + `sort=target_email`, unknown status → 400. Mesh:
  4 agents carry `display_name`, `CORP-LAPTOP-1` present. UI halves
  vitest-locked (796) on the field-proven devices-grid kit.
