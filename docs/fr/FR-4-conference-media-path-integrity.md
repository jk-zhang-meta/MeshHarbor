# FR-4: Conference media-path integrity — every mediasoup-serving node forwards the RTC range, and a dead media path is loud

**Status:** shipped + field-verified 2026-08-27 (retroactive FR for the 2026-08-26 "no
video" incident arc). Tracking issue: [#776](https://github.com/jk-zhang-meta/MeshHarbor/issues/776).

## Goal

Two (or more) participants in the same room call see and hear each other **regardless of
which pod their tenant hashes onto**. Concretely: the mediasoup RTC media path (UDP/TCP
40000–49999 to each pod's announced public IP) works on **every** node that can host a
meshharbor pod, keeps working across host reboots and provisioning re-runs, and a broken
media path is **loud** — a WARN in the pod log within seconds and a GitHub issue from a
weekly automated audit — never again "signalling green, video black, nothing logged".

## Incident (field evidence, 2026-08-26 21:57–22:01Z)

Reported: no remote video in the Grox room `69a1dbc8d2000f26adc875d5` from any pairing
(neo16 Chrome ↔ MacBook Safari, same user; neo16 ↔ Rozalina's Chrome), while chat,
presence and the call UI worked. Pod logs showed **all three connections on ONE pod**
(worker-2 / zeus, `10.10.20.11`) with textbook signalling: `media:join` → transports
created **and connected** → audio+video producers → consumers for every remote producer.
Zero RTP flowed.

Root cause: **zeus never had the RTC-range forwarding.** Browsers send mediasoup RTP
straight at each pod's announced public IP (S6 per-node map:
`MESHHARBOR__MEDIASOUP__ANNOUNCED_IP_MAP`, worker-2 → `5.9.157.226`), and the worker VMs sit
behind libvirt NAT — the physical host must DNAT the range into the VM. In
`k8s-cluster-multi` the range was modeled as a *jupiter-only extra* from the single-pod
era (flag literally named `host_firewall_jupiter_extra`;
`coturn_dnat_rules.zeus.port_ranges` lacked `"40000:49999"`). S6 (2026-08-02) put the
second pod on zeus's worker-2 and the model never followed, so every conference whose
tenant hashed onto the zeus pod was media-dead from the 2-pod cutover on.

Why it stayed invisible for ~3.5 weeks:

- `connect_transport` only **records** the client's DTLS parameters
  (`crates/services/src/media/room_manager.rs`) — it proves nothing about packets, so
  every server-side log line was green while ICE died at the host firewall.
- Tenant-affinity hashing (`hash <tenant-key> consistent`) makes a per-NODE break
  **tenant-selective**: a consistent subset of orgs broken, the rest fine — which reads
  as an app bug, not infra. ("Works for org A, dead for org B" ⇒ suspect the node.)
- The C-4 media claim-or-route layer was *not* involved and needed no change — the
  incident call had all participants on one pod.

## Key design (4 layers, ownership order)

| # | Layer | Where | Mechanism |
|---|-------|-------|-----------|
| 1 | **Provisioning (source of truth)** | `k8s-cluster-multi` `b02b91a` | `coturn_dnat_rules.<host>.port_ranges` includes `"40000:49999"` for every meshharbor-hosting node; flag renamed → `host_firewall_mediasoup_rtc` (true jupiter+zeus, false mars). Playbook `11-host-networking` renders `/usr/local/bin/coturn-iptables.sh`, **flushes+rebuilds** the COTURN chains from the vars, and installs the boot service — reboots and re-runs converge to the model; a hand-fix without the model **reverts by design**. Run with `.env` sourced (else hosts resolve to TEST-NET placeholders). |
| 2 | **Persisted live state** | zeus + jupiter | 7-rule contract live (mangle `COTURN_TTL` sport-range TTL 64; nat `COTURN_DNAT`/`COTURN_OUTPUT_DNAT` tcp+udp dport-range → VM; `COTURN_SNAT` sport-range → public IP) + `iptables-save` to `/etc/iptables/rules.v4`. |
| 3 | **Drift guard** | `meshharbor-deploy` `b0d0021`+`3c53516` | `scripts/mediasoup-rtc-forwarding.sh` (`check`/`apply` on the host, knows zeus+jupiter, validates live rules AND the persisted file, `iptables-restore --test` after apply) + `scripts/mediasoup-rtc-forwarding-audit.sh` weekly cron on the build host (Mon 04:15 UTC) reaching both hosts **over the overlay mesh** (direct public-IP ssh from the build host is denied); files a GitHub issue on drift. |
| 4 | **Runtime detection (app)** | PR #752 → master `cf8e8bb7` | `RoomManager::spawn_media_path_watchdog`: 15 s after each successful `connect_transport`, a **weak-handle** task WARNs `media transport has no DTLS 15s after connect_transport …` with resolved announced IP + ICE/DTLS state + transport id (weak so the watchdog never extends a transport's life past the leave). `media:join` ICE diagnostics now log the pod's **resolved** per-pod announced IP — the static setting printed jupiter's IP while the candidates said zeus, which misled the diagnosis. `connect_transport` also releases its DashMap shard guards before awaiting (the deadlock pattern `sample_transports` documents). ⚠️ `DtlsState` imports as `mediasoup::types::data_structures::DtlsState` — the prelude doesn't re-export it and `mediasoup::data_structures` is private. |

Considered and rejected:

- **Force media through the TURN relay** (`force_relay=true`) — latency + coturn load for
  no gain; the direct path is the product.
- **Routed public IPs per VM** (no NAT) — removes the DNAT class entirely but costs
  money + renumbering; the DNAT design is field-proven on jupiter since S6.
- **Making the same-channel SHA-of-signalling "prove" media** — nothing at the
  signalling layer can; only packet-level state (DTLS) can, hence layer 4.

## Acceptance criteria (all field-verified 2026-08-27)

- [x] UDP probe from an external client to `5.9.157.226:4xxxx` is DNAT'd onto the
      worker-2 VM — tcpdump on zeus `virbr1` shows `37.63.x.x → 10.10.20.11:44444/44445`
      (verified twice: after the hand fix AND after the playbook rebuild)
- [x] A real 2-connection call through the **zeus** pod renders mutual live video
      (two Chrome tabs, goran, room `…875d5`: each tab showed the other's camera)
- [x] `mediasoup-rtc-forwarding.sh check` exits 0 on zeus AND jupiter (live + file)
- [x] Playbook `11-host-networking --limit zeus,jupiter`: 0 failed (zeus changed=4,
      jupiter changed=3), contract green after, boot script carries the range
- [x] Weekly audit end-to-end dry-run from the build host over the mesh: `AUDIT OK`
- [x] Watchdog + diagnostics merged (#752) with CI **and** the full integration suite
      green on the PR head and again on master `cf8e8bb7`
- [x] CLAUDE.md documents the ownership chain + the tenant-selective failure signature

## Field-verification log

- 2026-08-26 ~22:1xZ — zeus live rules applied; `iptables-restore --test` PASSED;
  DNAT probe: 3/3 packets forwarded to the VM.
- 2026-08-26 ~22:15Z — two-tab call in the real Grox room: mutual live video both
  directions through the zeus pod (visual confirmation, then hung up).
- 2026-08-27 — `k8s-cluster-multi` playbook applied to zeus+jupiter; post-rebuild DNAT
  probe 2/2 forwarded; drift check green on both hosts. (The chain rebuild transiently
  demoted the fleet hosts' mesh carriers to DERP; they re-promoted — expected.)
- 2026-08-27 — audit cron dry-run: `AUDIT OK`; conference integration tests 29/30
  locally (the 1 failure reproduces identically on master — pre-existing, filed #754);
  integration suite green in CI (where that test is an environment skip).

## Out of scope

- #754 — `call/join` after last-leave auto-end never restores `conference_status:
  in_progress`, so the C-4 claim gate refuses the re-join's `media:join` (and
  `call_join` broadcasts a hardcoded `"in_progress"`); pre-existing, tracked separately.
- Pinning the host agents' ephemeral UDP ports outside 40000–49999 — zeus's `meshharbord`
  holds sockets inside the range (one bound to the public IP); DNAT only captures NEW
  inbound flows and established carriers ride conntrack, and jupiter has run with the
  overlap since S6. Optional hardening if cold-inbound dials to fleet hosts ever matter.
  → **They did** ([#1665](https://github.com/jk-zhang-meta/MeshHarbor/issues/1665)): after a
  roll both hosts sat on DERP. Done 2026-09-26: the overlay port is pinned to 21640 and
  `ip_local_reserved_ports=40000-49999` keeps ephemeral sockets out
  (`docs/deployment.md` › Cluster hosts).

## Related

- Incident fix PR: [#752](https://github.com/jk-zhang-meta/MeshHarbor/pull/752) (master `cf8e8bb7`)
- Follow-up bug: [#754](https://github.com/jk-zhang-meta/MeshHarbor/issues/754)
- `k8s-cluster-multi` `b02b91a` · `meshharbor-deploy` `b0d0021`, `3c53516`
- CLAUDE.md → Deployment → "Mediasoup RTC-range host forwarding (2026-08-26 incident)"
