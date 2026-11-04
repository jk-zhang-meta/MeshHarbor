# FR-40: Rotate a device's overlay key from the dashboard — the server orders a re-mint it never sees

Status: **P1 COMPLETE and field-verified (0.4.26 + web `v20260830-6a166a1ec9f7`; five rotations on CORPLAP-3, one on CORPLAP-2, every one clean; P1b/P1c/P1d closed the report/redelivery defects the field runs found); P2 (retired keys) and P3 (CLI) open** (2026-08-30). **2026-10-07:** the three criteria the fleet could never show — the pre-verb refusal (AC4), the offline-queued rotation on connect (AC5) and the device kill switch (AC7) — field-read on two throwaway Ubuntu VMs enrolled permanently against prod (`0.4.116`, and `0.4.24` pinned with `auto_update=false`), every read pairing a refusal arm with a success arm; the shipped design is documented in [`docs/overlay-key-rotation.md`](../overlay-key-rotation.md). Tracking issue: `FR-40` (#962).
Sibling of the remote-configuration work (`docs/remote-config.md`) — same push / report-back /
reconcile-on-connect shape — and of `rc:agent.update`, which is the operator's mental model for
it ("update now", but for the key).

## Goal

An admin can retire a device's WireGuard overlay identity from the device grid, the way they
push an update: the device mints a fresh key **locally**, persists it, re-joins the mesh under
it, every peer reinstalls it within seconds, the old key is useless everywhere, and the
dashboard shows — honestly — whether that happened. A device that is offline rotates on its
next connect. The server never holds, transports or chooses a private key at any step.

## What happened (field evidence, 2026-08-29)

A diagnostic over the Fleet RPC read CORPLAP-3's non-secret overlay/relay/encoder settings with
`Select-String -Path config.toml -Pattern '^(overlay|relay|…)'`. `overlay_wg_secret_key`
starts with `overlay`. One value — the primary org's WG secret of one single-org device — landed
in a session transcript (a local file plus the model API). The agent token and the SSH host key
were not printed (re-checked with a masked scan of the transcript, 2026-08-30).

There is **no remedy for that today** short of re-enrolling the device: no rotation on the CLI,
none over LocalAPI (`overlay_wg_secret_key` is deliberately unwritable there,
`crates/agent-core/src/config_surface.rs:2289-2148`), none on the web. Re-enrolling needs a fresh
enrollment token, local or `exec` access as SYSTEM/root, a daemon restart, and it is not what an
operator reaches for when a key leaks — they reach for "rotate".

What the key is worth to whoever holds it: it is the device's whole **data-plane identity**. A
holder can complete WireGuard handshakes as that node with every peer that has its public key
installed — everything the overlay ACL grants the node, and its *inbound* (SSH grants dial the
overlay address, FR-19 relay sessions, tunnel routes). The control plane is NOT reachable with it
(joins and DERP registration need the agent JWT, `crates/api/src/ws/derp.rs:230-254`), and DERP
additionally refuses a registration whose pubkey is not the row's (`derp.rs:339-362`).

## What is in force today (verified on master `f6bc3ffd`)

| piece | where | note |
|---|---|---|
| primary key mint | `agents/meshharbord/src/main.rs:3428-3435` | lazy, at daemon start, `WgKeypair::generate()` → `config::save`; the ONLY primary mint |
| secondary-org mint | `crates/agent-core/src/enrollment.rs:621-622` | at enroll-append; never copied from the primary (cross-org correlation) |
| storage | `crates/agent-core/src/config.rs:1855` (primary), `:1985` (`OrgEntry`), `for_org` at `:2119-2147` | the key is **per org** — `for_org` scopes it, unlike `exec_enabled`/`ssh_*` which are host-global |
| atomic save | `config.rs:3340` | tmp + `sync_all` + 0600/ACL + `.prev` + rename, under the daemon-wide write lock (`org_join.rs:48`) |
| how a session gets its key | `agents/meshharbord/src/signaling.rs:444-449`, `:881-883`; `overlay.rs:210-217` | from the in-memory `AgentConfig` snapshot taken at start — **never re-read from disk per session** |
| runtime identity | `agents/meshharbord/src/overlay.rs:79-86` (`RuntimeFingerprint::same_shape` includes `wg_public_key`), `:236-243`, `:430-438` | a changed secret already fails re-attach and rebuilds the runtime |
| existing per-org cycle | `main.rs:2883-2904` (`spawn_org`: stop the previous loop, re-load config from disk, respawn) | the primary loop has NO stop handle |
| server join | `crates/api/src/ws/overlay.rs:232`, `:279-297` (`wg_key_taken_by_other`, machine-scoped ⇒ a same-machine rotation is allowed), `:299-390` (`rehydrate` stores `wg_public_key` + `key_epoch`) | `key_epoch` is stored and **read by nothing** (`models.rs:2904`; the agent always sends 0, `runtime.rs:1951`) |
| peer fan-out | `overlay.rs:531-561` → `OverlayNetmapDelta { upserts, removes }` (`signaling.rs:3897`) | an upsert IS the update; the re-join already carries the new key to every peer |
| peer reinstall | `crates/tunnel-core/src/overlay/runtime/establish.rs:1147-1180` | "peer's WG public key changed — reinstalling its carrier" (`PeerRoute::Keep`) |
| DERP | `crates/api/src/ws/derp.rs:339-362` (pubkey must equal the row's), `derp_acl.rs:99-140` rebuilt on every join (`overlay.rs:481-490`) | the row must carry the new key BEFORE the node re-registers — the join does exactly that |
| the push precedent | `crates/api/src/routes/remote_control.rs:831-872` (`trigger_agent_update`, `MANAGE_AGENTS`, `Hub::send_to_agent`), agent arm `signaling.rs:2767-2789` (primary-only) | `UpdateNow` is sent BLIND — no cap gate |
| the report-back precedent | `ClientMsg::ConfigStatus` (`signaling.rs:505`), `record_config_report` (`ws/remote_control.rs:940-985`), `config_audit` (`models.rs:5145-5163`) | the shape to copy: revision-bumped request, device reports the revision, server resolves ONE state |
| capability verbs | `crates/remote_control/src/models.rs:271-384` | `RpcCap` — no rotation verb exists |
| UI | `ui/src/components/admin/AgentsSection.vue:1918-1906`, `ui/src/stores/agents.ts:749-704` | "Update now"; **no view shows the overlay public key anywhere** |
| retired keys | — | none: `wg_key_taken_by_other` is live-scoped, a tombstone's key neither blocks nor denies |

## Design

### Invariants

1. **The server never sees a private key.** The push is an *order to mint*, never a delivery.
   `DesiredConfig` stays structurally unable to carry a key; the only key-shaped field on the
   wire is a PUBLIC key in the device's report, and a test asserts the serialised order has no
   such field.
2. **Per org, honoured on any org's WS.** The key is per org by design (`for_org`), so org B's
   admin rotating org B's key on a shared host touches nothing of org A's. This is the opposite
   of `rc:agent.update` / config push, which are host-global and therefore primary-only
   (`docs/remote-config.md` §4). The handler must not copy that guard.
3. **Persist before anything else.** Mint → save under the write lock → *then* report and
   reconnect. If the save fails the identity stays and the device reports `failed`, the same rule
   the SSH host key follows (an unpersisted key would be lost at the next restart and the device
   would come back as the key it just retired).
4. **One data-plane path.** The rotation reuses a reconnect: the WS loop that received the order
   replaces the key in its own snapshot and re-enters `connect_once`; `maybe_start` sees the
   fingerprint mismatch and rebuilds the runtime; the join carries the new pubkey; the server's
   existing upsert fan-out and the peers' existing reinstall arm do the rest. Nothing new is
   added to the packet path.
5. **Immediate and disruptive, by design.** The rotation ends every session the device carries
   on that org (RC, SSH over the overlay, tunnel flows) — a key that leaked must not wait for
   the holder's session to end. The confirm dialog says so. ⚠️ A corp-VPN host may come back
   relay-locked after the cycle (the renumber runbook's caveat, `docs/multi-org.md`).
6. **The device reports back, and the join is the proof.** A report is a claim by the device
   (`ssh_activity` sense); the join under the new key is what the server can verify. The
   dashboard state is resolved ONCE server-side from `{request, report, node row}` — never in the
   client.

### The order — `rc:agent.key_rotate`

`ServerMsg::KeyRotate { request_id }`. Minted by `POST /api/tenant/{tid}/agent/{id}/overlay-key/rotate`
(`MANAGE_AGENTS` — this grants nothing, it retires something; no `EXEC_DEVICE`/`SSH_DEVICE`
bit is involved). The route:

1. resolves the device in the tenant (404 otherwise, no existence leak);
2. records the request on the agent row: `key_rotation = { request_id, requested_at, requested_by }`
   (the *desired state*, so the offline case has somewhere to live);
3. if the device is online **and** advertises `key-rotate`: pushes → `delivered: true`;
   online without the verb → `refused: agent_unsupported` (409 — the old-agent frame would
   evaporate silently, the failure `RpcCap::Config`'s doc was written about); offline → `queued`;
4. writes ONE audit row for either arm (`key_rotation_audit`, 90 d TTL; `decide()` returns
   `Result<Pushed|Queued, DenyReason>` and a single call site records both, the `agent_ssh::dispatch`
   shape, so a new refusal cannot forget to audit itself);
5. per-device ceiling: one request per 60 s (`rate_limit.rs`, after the identity gates so the
   refusal is attributable).

Capability: `RpcCap::KeyRotate` (wire `key-rotate`; equality match, `ALL` entry, wire string
locked by test).

### On the device

Handler in the WS loop that received the order (`signaling.rs`, next to `ConfigPush`):

1. kill switch `overlay_key_rotation` (tribool, default on; config-surface key + env
   `ROOMLERD_OVERLAY_KEY_ROTATION`) — off ⇒ report `refused: disabled`;
2. rate limit: an order < 60 s after the last rotation on this org ⇒ `refused: rate_limited`;
3. `WgKeypair::generate()` (same mint as enrollment); take the daemon write lock,
   `config::load(path)`, set `overlay_wg_secret_key` on the primary scalar or on the `[[orgs]]`
   entry whose `tenant_id` is this loop's, bump `overlay_wg_key_epoch` (new, persisted next to
   the key; `0` when absent), `config::save`;
4. report `rc:agent.key_rotated { request_id, outcome, old_public_key, new_public_key, key_epoch, detail }`
   on the CURRENT session (it is about to end);
5. replace the key + epoch in the loop's own `cfg` snapshot and return
   `ConnectError::KeyRotated` — an immediate reconnect (no stagger: this is one device, not a
   fleet event). `maybe_start` rebuilds the runtime (fingerprint mismatch), the join sends the
   new pubkey and the bumped `key_epoch`.

Builds without an overlay surface refuse `unsupported` and never advertise the verb.
`overlay_wg_secret_key` stays unwritable over LocalAPI — rotation is an ACTION, not a config
write, and the local `roomler overlay rotate-key` (P3) goes through the same action.

### Re-join and the mesh

Unchanged code, now exercised on purpose: `wg_key_taken_by_other` admits the same machine;
`rehydrate` stores the new key + epoch; the per-recipient upsert fan-out carries it; peers hit
the reinstall arm; DERP ACL is rebuilt. ⚠️ Known bounded transient: `derp_acl::rebuild` is
spawned at join, so the node's first DERP frames under the new key may be denied for
milliseconds until the table lands — WireGuard's handshake retry covers it. Measure it in the
field rather than adding a barrier.

### Report-back and the state the dashboard shows

Server ingest of `rc:agent.key_rotated` stores `key_rotation.report` on the agent row (the
claim). `KeyRotationState` is resolved server-side from request + report + the live node row:

| state | meaning | operator's move |
|---|---|---|
| `none` | never requested | — |
| `queued` | requested, device offline, no report | wait; it rotates on connect |
| `delivered` | pushed, no report yet | wait a few seconds |
| `rotated` | report says rotated **and** the node row's `wg_public_key == report.new_public_key` | done |
| `reported_not_joined` | report says rotated, but the row still shows the old key | the re-join failed — read the device log |
| `refused: <reason>` | disabled / rate_limited / unsupported / failed | fix the stated thing |
| `unsupported` | device online without the verb | update the device |

⚠️ Compare `request_id`s, not outcomes — a report about an earlier request says nothing about
this one (the remote-config lesson). The device row also gains `overlay_public_key` (short form,
copyable) and `key_epoch`, so the operator can SEE the key change instead of trusting a chip.

### Offline devices — reconcile on connect

At agent register (`ws/remote_control.rs:176-195`, where `ConfigPush` reconciles), a pending
`key_rotation` with no report is pushed if the hello advertises `key-rotate` — the same path as
the online case, so it runs on every connect rather than only when nobody is watching.

### Retired keys (P2)

On a pubkey change at join, the old key is appended to the node row's `retired_keys[]`
(`{ public_key, key_epoch, retired_at, reason: rotate|rejoin }`, multikey index). A join or a
DERP registration presenting a retired key is refused with its own reason (`key_retired`) —
defense in depth for the `.prev`-rollback and the "attacker holds both the WG key and the agent
token" cases — and, when the device advertises `key-rotate`, the refusal is answered with a
`KeyRotate` order instead of a dead join: a device that rolled back to a retired key heals itself.
Also adds the missing index on `(network_id, wg_public_key)` (`wg_key_taken_by_other` is an
unindexed `find_one` per join today).

### Multi-org

| | `rc:agent.update` / config push | `rc:agent.key_rotate` |
|---|---|---|
| scope of the thing changed | host-global | this org's key only |
| honoured on | primary WS only | the WS the order arrived on |
| disk write | scalar keys | primary scalar OR the matching `[[orgs]]` entry |

### Kill switches

`overlay_key_rotation` (device, default on). No server switch: the route is admin-initiated
and permission-gated; a defective push is stopped by the device switch.

## Phases

| phase | what | kill switch | status |
|---|---|---|---|
| P0 | spec + issue + ledger claim | — | this |
| P1 | verb + order + device mint/persist/report/reconnect + route + audit + ceiling + reconcile-on-connect + UI action/state/pubkey column; release | `overlay_key_rotation` | shipped (#963, `agent-v0.4.25`), field-verified |
| P1b | the duplicate-delivery race found by the first field run: a freshly delivered order (< 120 s) is not re-pushed on the device's own reconnect, and a refusal never overwrites a `rotated` report for the same order | — | shipped (#978); held in run 2 |
| P1c | the join is the proof: the order snapshots the device's public key and the state resolves `rotated` from a verified identity change (report or no report — the report rides the dying session and was lost in run 2); the agent re-sends its `rotated` report on the next session, per org | — | shipped (#979, `agent-v0.4.26`); re-send field-verified twice |
| P1d | an order the device has already executed (its join under a key ≠ `public_key_before`) is satisfied and never re-delivered — one click, one rotation, whatever became of the report | — | shipped (#981), deployed `v20260830-6a166a1ec9f7`; the P1d pod roll re-delivered nothing |
| **Docs** 📘 (2026-10-07, added retroactively — see the criterion) | [`docs/overlay-key-rotation.md`](../overlay-key-rotation.md): the order and the four cells of its decision, the device's mint → persist → report → reconnect with the persist-first rule, the join as the proof (three records, three trust levels), the server-resolved states the chip names, reconcile-on-connect and the three field-run races it must not re-run, the kill switch, what is deliberately not rotated, the field table, a code map; cross-linked from `overlay-communication.md` §1, `security-baseline.md` §4, `api.md`, `real-time.md` and `data-model.md`; a `docs/README.md` row and map node | n/a | written with the AC4/AC5/AC7 field reads; ticked when on master |
| P2 | retired keys: refuse at join + DERP, self-heal order, pubkey index | none needed (refusal is fail-closed) | open |
| P3 | `roomler overlay rotate-key [--org]` over LocalAPI (break-glass when the control plane is the compromised thing); tunnel-only clients (`roomler` standalone) | — | open |

## Acceptance criteria (field, the real device: CORPLAP-3, single org, `0.4.25+`; AC4 / AC5 / AC7 on throwaway VMs against prod, 2026-10-07)

- [x] the route on a device advertising the verb returns `delivered`; the device log shows
      mint → save → report → reconnect; the node row's `wg_public_key` and `key_epoch` change
      within 10 s and the dashboard reads `rotated` (final run 02:09 UTC: order :08.9 → epoch 5 at :09.4 → join :10.2 → report ingested :10.23 → `rotated` in the UI within 5 s)
- [x] neo16's daemon reinstalled CORPLAP-3 under the NEW public key (`peer's WG public key changed - reinstalling its carrier`, 00:19:39, 12 s after the re-join) and traffic flows: overlay ping 4/4 at 84–97 ms within 60 s of the click (`roomler peers --json` carries no key field — the log line is the evidence)
- [x] the old public key is on no peer's WG device afterwards — `peer's WG public key changed — reinstalling its carrier` on neo16 AND mars, 18 ms after the join (`remove_peer_state` drops the old key; `roomler peers --json` carries no key field, so the log line is the evidence)
- [x] a device on `0.4.24` or older (no verb) gets `unsupported` on the route, not a spinner — integration-tested (`an_offline_device_is_queued_and_the_state_is_honest_about_it`); **field-read 2026-10-07 on a throwaway VM pinned at `0.4.24`** (`auto_update = false`, so it could not do what every fleet device did and update past the verb before the click; its hello `rpc` carried no `key-rotate`): online → the route answered **409 `agent_unsupported`** ("predates overlay-key rotation (needs 0.4.25 or later) — push an update first") in 2 ms, audited, and recorded **nothing** on the row (no chip, nothing in flight); ordered while offline → `queued`, the state resolved **`unsupported`** from the row's last-hello caps three seconds later, before the device had reconnected, and on connect the pod logged `overlay-key rotation not ordered — this device's agent predates rc:agent.key_rotate; update it first` while the row's key and epoch (`9bf++x5I…` e0) stayed unchanged through the 30 s read window. The negative control is the same route on the `0.4.116` VM minutes earlier: `pushed`. Never read on the fleet itself — every fleet device had auto-updated past the verb by the time this was first tried
- [x] a device that is offline is `queued`, and rotates on its next connect with no operator action — integration-tested (queued); the connect-time delivery was first exercised by the third cycle (an order delivered on connect at 01:30:36 and 01:34:54), not by an offline device; **field-read 2026-10-07 on a throwaway VM (`0.4.116`, permanent enrollment)**: daemon stopped (`is_online: false`) → the order answered `{dispatch: "queued", delivered: false}` and the state read `queued` with no `delivered_at`; the daemon was started and nothing else was touched → the pod logged `overlay-key rotation order delivered on connect` at the hello (02:32:07.181, which is also the row's `delivered_at` — 19 s after `requested_at`, the connect and not the click), the device logged `new overlay key persisted` 7 ms later and `key_epoch=2`, re-sent its report on the new session, the row's key changed (`pzMXbTsc…` e1 → `JmpHU4PO…` e2) and the state read `rotated` at the first sample 8 s after the start; the anchor peer reinstalled the carrier 13 ms after the re-join; 135 s later — past `REDELIVER_AFTER_SECS` — the epoch was still 2 and the pod held exactly one `delivered on connect` line for the order, so the rotation's own reconnect re-delivered nothing (P1b/P1d held)
- [x] a second click within 60 s is `refused: rate_limited` and audited (run 2: the second order 3 s after the first → 409 `rate_limited`, logged by the pod; the audit row is the integration test's)
- [x] `overlay_key_rotation = false` on the device ⇒ `refused: disabled`, key unchanged — unit-tested (config surface); **field-read 2026-10-07 on a throwaway VM (`0.4.116`; the switch flipped at the top of `/etc/roomler/config.toml` and the daemon restarted — the restart a corp laptop could never be given)**: the server still `pushed` (`delivered: true` — it cannot see a device switch), the device answered `rc:agent.key_rotate refused — overlay_key_rotation=false on this device` 5 ms after the order, the pod ingested `outcome=Disabled key_epoch=0`, the state read `refused` with `report.detail = "overlay_key_rotation=false on the device"`, and the row's public key and epoch (`OzZbtG7B…` e0) were byte-identical before the order, 8 s after it, and after the next restart — which also did not re-push the refused order (a report for it exists). Positive control on the same device: switch back to `true` + restart → the next order rotated (`new overlay key persisted` 9 ms after the order, e0 → e1, `rotated` at the first sample 4 s later, the anchor peer reinstalled its carrier 12 ms after the re-join)
- [x] the request and the report carry public keys only — a test asserts the serialised
      `KeyRotate` frame has no key-shaped field, and the audit row stores none
- [ ] (P2) a join presenting a retired key is refused `key_retired`, and a device with the verb
      is ordered to rotate instead of staying off-mesh
- [ ] **Docs updated/created with diagrams, linked from `docs/README.md`** —
      [`docs/overlay-key-rotation.md`](../overlay-key-rotation.md) in the house style of the
      other `docs/*.md`: the rotation end to end as a `mermaid` sequence diagram, the
      server-side state resolution as a `mermaid` flowchart, the route's four decision cells,
      the device's steps with the persist-first rule, the three records and their trust
      levels (order · decision · claim · proof), the states the chip names and the operator's
      move for each, reconcile-on-connect and the three field-run races it must not re-run,
      the kill switch and why it defaults on, what is deliberately not rotated, the field
      table and a code map with `file:line` anchors verified against master; indexed in
      `docs/README.md` (a row and a map node) and cross-linked from
      `overlay-communication.md` §1, `security-baseline.md` §4, `api.md`, `real-time.md` and
      `data-model.md`. ⚠️ **Added retroactively (2026-10-07)**: FR-40 opened on 2026-08-29,
      before the docs-before-close rule (#1401, 2026-09-05), and a close after that date
      binds it. Ticked when the page is on master

## Open decisions

- **Self-heal on a retired key (P2)** — auto-order vs. surface-only. Leaning auto-order: the
  alternative is a device that is on the control plane and off the mesh with nothing to press.
- **Whether the ledger of retired keys should live per network or per node.** Per node keeps the
  forensic record with the holder (the tombstone convention); the index makes the check cheap
  either way.
- **Bulk rotation** — deliberately not offered. Rotating a fleet at once is a storm (every peer
  reinstalls every carrier); if it is ever needed it is a paced job, not a button.

## Out of scope / what this does NOT rotate

- The **agent token** (JWT, 1 y) — a different identity with a different fix (`token_epoch`,
  Known Issues). A leaked token is a control-plane compromise; this FR is about the data-plane
  key.
- The **SSH host key** (`ssh_host_key`) — clients pin it; rotating it is a client-side TOFU
  event and deserves its own runbook.
- Scrubbing `config.toml.prev` — the retired key remains on disk there until the next save; an
  on-host reader of `.prev` can read `config.toml` too, so it is not a boundary this could
  defend. P2's retired list makes the copy worthless off-host.
- Tunnel-only clients (P3) and the standalone `roomler` CLI's own key.

## Field-verification log

| date | build | note |
|---|---|---|
| 2026-08-30 | — | P0: exposure bounded to ONE device / ONE key by a masked transcript scan; no token, no SSH host key. |
| 2026-08-30 00:19 UTC | CORPLAP-3 `0.4.25`, web `v20260830-3cde7568624e` | **First field run**, ordered from the device grid. Device log: `rc:agent.key_rotate — new overlay key persisted` (00:19:26.031, old `148DYcQn…`) → `overlay key rotated — reconnecting … key_epoch=1` (.335) → `rc:overlay.join sent` (00:19:27.127); `config.toml` `overlay_wg_key_epoch = 1`; server identity `1xbYDyZ2qm… / e1` within the first API sample; neo16 reinstalled the peer at 00:19:39 and overlay ping to 100.65.4.30 ran 4/4 at 84–97 ms. **Defect (P1b)**: 00:19:27.157 — 30 ms after the join — the reconnect's register re-pushed the SAME order (its `rotated` report, sent on the dying session and written by a spawned task, had not landed), the device refused the duplicate under its 60 s ceiling, and that refusal overwrote the `rotated` report ⇒ the dashboard read `refused (rate_limited)` for a rotation that succeeded. Fixed by `should_redeliver` (no re-push inside 120 s of delivery) + a conditional report write (a refusal never overwrites a `rotated` report for the same order). Second run pending on the fix. |
| 2026-08-30 00:55 UTC | CORPLAP-3 `0.4.25`, web `v20260830-e936b19ac434` (P1b) | **Second field run.** Order …8b96e7 at 00:55:05.99; device: mint+persist (00:55:06.163, old `1xbYDyZ2qm…`) → `key_epoch=2` (.465) → join (00:55:07.234), **no duplicate refusal** (P1b held); the immediate second order refused `rate_limited` (409) at 00:55:09.10; neo16 reinstalled the peer at 00:55:19.64, overlay ping 85 ms; identity `rb/lMECrr2… / e2`. **Finding (P1c)**: the pods logged no report ingest — the `rc:agent.key_rotated` frame on the dying session was lost, so the state stayed `delivered` although the server had verified the new key at the join. Fix: the order snapshots the device's public key (`public_key_before`) and the state resolves `rotated` from the verified identity change; the agent also re-sends the report on the next session. |
| 2026-08-30 01:30–01:35 UTC | web `v20260830-a964d88d6244` (P1c), CORPLAP-3 `0.4.25` → `0.4.26` | **Third cycle, unordered.** The run-2 order (report lost) was re-delivered by reconcile-on-connect twice — at the P1c pod roll (01:30:36 → e3) and at the 0.4.26 restart (01:34:54 → e4): the P1b window had expired and the order predates the identity snapshot. The 0.4.26 agent **re-sent its report on the new session** (01:34:55.337) and the pod ingested it 26 ms later ⇒ `rotated` (P1c agent half verified). The mesh healed after each rotation (neo16 reinstalls 01:30:50 and 01:35:07). Lesson → P1d: a satisfied order (verified identity change after the order) is never re-delivered. |
| 2026-08-30 02:09 UTC | web `v20260830-6a166a1ec9f7` (P1d), CORPLAP-3 `0.4.26` | **Final ordered rotation.** Order 02:09:08.9 → `new overlay key persisted` :09.085 → `key_epoch=5` :09.389 → re-sent report :10.210 → join :10.223 → pod ingest :10.229 (the dying-session copy was lost again — the re-send is the reliable path); `public_key_before` recorded; UI `rotated` within 5 s; neo16 and mars reinstalled the peer 18 ms after the join (⚠️ neo16's clock is 12 s ahead of the server — the earlier '+12 s' reinstall latency was that offset). CORPLAP-2 (auto-updated to 0.4.26) was rotated too by a refusal probe that found the verb present — clean, epoch 1. |
| 2026-10-07 02:28–02:36 UTC | two throwaway Ubuntu 24.04 VMs on the vmtest host, enrolled **permanently** (not ephemeral — an ephemeral row self-unenrolls on the very restarts these reads need) against prod on the current image: VM-A `0.4.116`, VM-B `0.4.24` pinned with `auto_update = false` | **AC7 / AC5 / AC4 field reads** — the three the fleet could never give: every real device auto-updates past the verb, and no corp laptop can be restarted for a kill switch. The fixes predate the reads, so there is no earlier deploy to fail on; instead each read pairs a refusal arm with a success arm on the same deploy. **AC7** — switch off + restart → order `pushed` 02:28:38.969 → device `refused — overlay_key_rotation=false` :38.974 → pod ingest `Disabled e0` :38.972 → state `refused`, key byte-identical (`OzZbtG7B…` e0) at :47 and after the next restart (which re-pushed nothing: a report exists); switch on + restart → order :30:40.470 → `new overlay key persisted` :40.479 → e1 :40.780 → hello + re-sent report :41.339 → pod ingest :41.340 → **the anchor reinstalled the peer :41.351** → `rotated`, `pzMXbTsc…` e1 at the first sample (+4 s). **AC5** — stop :31:23 → order :31:47.832 `{queued, delivered:false}` → state `queued` → start :32:07, hands off → pod `rotation order delivered on connect` :07.181 (= `delivered_at`, 19 s after the click) → persisted :07.188 → e2 → re-sent report :08.048 → ingest :08.108 → anchor reinstall :08.121 → `rotated`, `JmpHU4PO…` e2 at +8 s; at +135 s still e2, exactly one `delivered on connect` line for the order. **AC4** — VM-B online, hello `rpc` without `key-rotate` → **409 `agent_unsupported`** in 2 ms, audited, `key_rotation: null` afterwards and no frame ever reached the device; stopped → order :35:31 `queued` → state `unsupported` at :35:34 (from the row's caps, before any connect) → start → pod `not ordered — predates rc:agent.key_rotate` :35:50.434 → `9bf++x5I…` e0 unchanged at +15 s and +30 s. Both device rows deleted and both VMs destroyed afterwards; the harness is `fr40.sh` on the orchestrator host, driving the vmtest library's clone/boot/API primitives. |
