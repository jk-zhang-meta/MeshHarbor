# FR-2 — Pin-update downgrade guard

> **CLOSED 2026-08-27** — issue #770 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** jk-zhang-meta/MeshHarbor — `FR-2: pin-update downgrade guard` (filed with this doc)
**Status:** implemented, pending field verification

## Goal

A pinned update push (`POST /tenant/{tid}/agent/{aid}/update {"pin": …}` and the
bulk `POST /tenant/{tid}/agent/update`) must refuse to send a pin that is
**strictly older** than the version the target agent reports, unless the caller
passes `force: true`. The server is the one place that always knows both
versions at push time; today it forwards any pin verbatim.

## Root cause / field evidence (2026-08-27)

During the 0.4.x version-scheme migration, an operator-session script pinned the
transition release `agent-v0.3.0-rc.484` fleet-wide — planned hours earlier,
while a parallel session had meanwhile completed the flip and the fleet was
already on `0.4.1`. The script **printed** the live latest (`agent-v0.4.1`) and
every agent's `0.4.1` version, then pushed the stale pin anyway:

- Five `.deb` hosts (WSL sibling, scw-m2-asahi, zeus, jupiter, mars) actually
  **downgraded** to rc.484 (dpkg installs whatever it is handed) and had to be
  re-pinned up.
- Windows hosts refused at MSI level (MajorUpgrade blocks lower
  ProductVersions) — the only layer that pushed back.
- One accidental benefit: WINHOST-I (stuck on rc.475) needed exactly that
  rc.484 transition rung — proving the *deliberate* downgrade/side-grade path
  must stay available (`force`).

A check that merely prints is not a check; this FR moves the gate into the
server, where it cannot be skipped by a stale script.

## Key design (anchors verified against master @ `6defb220`)

- `crates/api/src/routes/remote_control.rs`
  - `TriggerUpdateRequest` (was `:742-747`) gains `force: bool`
    (`#[serde(default)]` — additive; existing callers unchanged).
  - New `release_ord(&str) -> Option<(u64,u64,u64,u64)>`: the same ordering
    tuple as the agent updater's `parse_version`
    (`agents/meshharbord/src/updater.rs:258-296`) — `rc.N` ranks `N`, finals
    rank `u64::MAX`, so `0.3.0-rc.482 < 0.4.0 < 0.4.1`. Tags and bare semvers
    both parse; unparseable → `None`.
  - New `pin_downgrade(pin, agent_version) -> Option<String>`: `Some(reason)`
    only for a **strict** downgrade. Equal = re-install (allowed — a normal
    recovery move). Unknown orderings are allowed: the guard cannot claim
    "downgrade" about what it cannot compare, and the agent's own artifact
    verification (`artifact_version.rs`) still gates what installs.
  - `trigger_agent_update` (was `:761-803`): refuses with **409 Conflict**
    naming both versions + the `force` hint.
  - `trigger_agents_update` (was `:825-956`): targets are collected as
    `(id, agent_version)` pairs; a stale pin **skips per agent** — the result
    row carries `refused: Some(reason)` and the response gains a `refused`
    count. A fleet push is never all-or-nothing over one already-updated
    device.
- Wire compatibility: all additions are additive (`force` defaults false;
  `refused` is skip-serialized when absent). The UI's stores parse field-level.

## Kill switch

Per-request `force: true` (the deliberate-downgrade escape hatch — crash
rollback, repro of an old build). No env toggle: the guard never blocks a
forced push, so there is nothing operational to disable.

## Acceptance criteria

- [x] Strictly-older pin on the single route → 409, message names both versions
- [x] `force: true` bypasses (integration-tested; not exercised against prod)
- [x] Equal pin (re-install) and newer pin pass untouched
- [x] Bulk: stale pin skips per agent (`results[].refused`, `refused` count);
      other targets still get the push
- [x] Unparseable pin or agent version → guard stays out of the way
- [x] Ordering locked against the updater's semantics (rc < final; finals by
      patch) in unit tests
- [ ] Field: a stale pin against a live 0.4.x agent answers 409 in prod; a
      current pin still delivers

## Open decisions

1. Should the devices UI surface `refused` rows distinctly in the update-all
   result toast? (Today they fold into "not delivered".)
2. Should `rc:agent.update` pushes originating from remote-config reconcile
   (if ever added) share this guard? Out of scope until such a path exists.

## Out of scope

- The agent-side pin handling (`updater::pin_version`) keeps accepting
  whatever the server forwards — rollback-to-`last_known_good_version` must
  keep working even when the server is the thing being rolled around.
- Guarding non-pinned pushes ("update to latest" can never downgrade — the
  agent's own `is_newer` check refuses).

## Field-verification log

- **2026-08-27, prod (`v20260827-1a4b35b8d855`) — ALL PASS, #770 closed.**
  Staged against the offline Windows straggler `WINHOST-H` (rc.458):
  stale pin rc.299 → **409** naming both versions; same pin `force:true` →
  200; newer rc.484 → 200 (deliberately left pinned — it is the transition
  rung that host needs before a 0.4.x MSI); bulk scoped to it with the stale
  pin → `refused:1` + per-row reason, `delivered:0`. Live-agent half:
  stale pin vs **CORPLAP-2 (online, 0.4.4)** → 409 — refused server-side
  before any push, zero device side effects. "Current pin still delivers"
  evidenced by the 08-26/27 shepherding pushes (rc.484 → 0.4.1 → 0.4.2,
  `delivered:true` fleet-wide) that ran through this same route.
