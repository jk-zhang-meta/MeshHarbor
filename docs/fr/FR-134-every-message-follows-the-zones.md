# FR-134: Every message follows the zones — the centre is a zone, and a device reaches it only through its zone's gateways

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record. Completes
> [FR-128](FR-128-the-centre-is-a-zone-of-its-own.md), whose P1 routed only a strict zone's devices
> through their zone's entries and let every other device dial the centre first.

## Goal (the user, 2026-11-24)

> 当建立分区以后，是必须指定这个分区的转发节点的，因为逻辑分区之间是通过转发节点即该逻辑分区的核心路由
> 节点转发的，所以我要扩展到无论什么消息都按照底层算法走这个，而不再像以前一样中央节点的控制信息也要求直连。

- **The centre is a zone.** Its only node is the centre's own host device. Geography never assigns a
  device to it; only an explicit pin does.
- **A zone names its gateways.** A zone with no gateway is refused at save.
- **One rule for every message.** A device in a zone reaches the centre only through its own zone's
  gateways, for every connection it makes to the centre: the control WebSocket, every HTTP client
  (enrollment refresh, logs, crash reports, preflight, the device view, remote config, exec results,
  the updater's manifest and downloads), DERP, and tunnel-client sockets. Only a zone's gateways, and
  the centre zone's own node, dial the centre directly: gateway to gateway, as between zones.
- **A gateway is its zone's entry by default.** No separate opt-in; its owner can still switch the
  entry off on that device.
- **Never stranded.** When every gateway of a device's zone is unreachable, the device dials the
  centre directly as a last resort, says so in its log and status, and goes back to its gateways as
  soon as one answers (CLAUDE.md: a mesh feature must never cost the operator their remote access).
- An organization without zones is unchanged.

## Why

Production on 2026-11-24: only one of ten zone gateways ran an entry (the CN zone's `tencent-sh`); the
non-CN zone had none, so all its devices could only dial the centre, and a failed direct connection
showed the device offline — the failure the zone model exists to remove.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Server: centre zone kind, zones must name a gateway, `path_for` = direct only for gateways and the centre zone | `app.management_entries = false` (everything direct, as before) | planned |
| P2 | Agent: a gateway serves the entry by default; every device→centre connection goes through the path ladder, DERP and the updater included; last-resort direct and its way back | device `MESHHARBORD_MANAGEMENT_ENTRIES=0` | planned |
| P3 | Field: both zones' gateways serving entries, every Linux device on its zone's entries, the centre zone with the centre's device | — | planned |

## Acceptance criteria

- [ ] **AC1.** A non-gateway device in any zone holds no connection to the centre while one of its
  zone's gateways answers (field: socket table on each device, red on the current deploy first).
- [ ] **AC2.** Every gateway of each zone serves the entry without a per-device setting (field).
- [ ] **AC3.** All of a zone's gateways down → the device reaches the centre directly within the
  ladder's bound and returns to a gateway when one answers (tests + field on a throwaway device).
- [ ] **AC4.** A zone without a gateway is refused; geography never places a device in the centre
  zone (tests).
- [ ] **AC5.** An org without zones and `management_entries = false` behave exactly as before (tests).
- [ ] **AC6 (docs).** `docs/business-isolation.md` and the overlay docs describe the rule (mermaid,
  anchors) and a row in [docs/README.md](../README.md).

## Out of scope

Browsers (the web console and the remote-desktop viewer) are not zone members and keep reaching the
centre as they do. Media paths between devices keep FR-124's per-zone ICE policy.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
