# FR-33: A VPN that captures the LAN prefix should say so — surface LAN capture in `status`, `why` and the RC path pill

Status: **P1 field-verified on 0.4.20 (2026-08-29); P2 field-verified on 0.4.59
(2026-09-04); P3 field-verified on 0.4.61 + the 2026-09-04 UI deploy, from a Chrome profile
(the first check ran from an Edge profile that gathers no host/srflx candidates at all — a
per-profile browser setting, see the field log). Every acceptance criterion field-verified,
kill switch cycled on CORPLAP-3 — CLOSED 2026-09-04.** Tracking issue: `FR-33` (#905).
Sibling of FR-9 (LAN relay diagnosis) and FR-31 (opening keyframe). Spec on master up front; the
design is known.

## The measurement that motivates it

2026-08-29: the operator reported `neo16 → CORPLAP-2` as a *quality regression*. It was not — the
pair had been relay-locked for **five days** because CORPLAP-2's Check Point Endpoint VPN carries
`192.168.68.0/25` + `192.168.68.128/25` via the VPN adapter (`Ethernet 3`, `172.30.245.31/19`)
at metric 1, beating the on-link `/24`. neo16's LAN handshakes arrive (CORPLAP-2's LAN socket
shows `rx=9155`) and are accepted as probes; CORPLAP-2's replies leave through the VPN and die.
Both ends logged `direct probe did not handshake within deadline; kept relay` ~45×/hour for
120 h, and every surface the operator reads said only `upgrading`, `relay`,
`blocked_by: penalty`.

Getting from that to the cause took `Find-NetRoute` on the device over Fleet RPC, a Mongo
histogram over both agents' logs, and the AnyConnect precedent from FR-9. A daemon that already
samples the effective route by LOOKUP (`crates/tunnel-core/src/overlay/netstate.rs:122` —
`GetBestRoute2` / `ip route get` / `route get`, precisely because "a corp capture rarely touches
`/0`") can answer this in one more lookup.

## Goal

When a host's own LAN prefix is routed through an interface other than the one that owns the
address, every place an operator reads a carrier verdict names the capture — so a relay on a LAN
pair is attributed to the VPN in seconds, not days, and is never again hunted as an encoder
regression. **Detect and surface only.** Routing around the capture is VPN policy evasion and
stays out of scope (operator's standing rule).

## Key design

1. **Detection (netstate, all three OSes).** For every LAN interface address in
   `NetSnapshot.ifaces` (`netstate.rs:134`), look up the route to another address inside the
   same prefix — a fixed neighbour address (our own address with its lowest bit flipped, off
   the network/broadcast edges), so the answer never depends on a peer existing. If the
   selected interface ≠ the owning interface, record
   `LanCapture { prefix, owner_ifref, via_ifref, via_name }`. Sampled where the default-route
   lookup already runs (`sample_snapshot`, `netstate.rs:438`): one lookup per LAN interface per
   snapshot. Onset and clear each produce ONE `NetDelta` with a one-line `summary`
   (`netstate.rs:160`) — the "LOG every silent drop" rule — never a per-snapshot line.
2. **`meshharbor status`** gains a line next to `srflx`, using the same shape
   (`agents/meshharbor-cli/src/localclient.rs:1237`):
   `lan         CAPTURED — 192.168.68.0/24 leaves via "Ethernet 3" (Check Point Virtual
   Network Adapter For Endpoint VPN Client); direct on the LAN is impossible while it does`
   and `lan         clear` otherwise. Wire: `NodeStatus.lan_capture: Option<LanCaptureStatus>`
   (`crates/localapi/src/lib.rs:89`), populated the way `srflx` is
   (`agents/meshharbord/src/localapi_state.rs:371` ← `runtime.rs:3230`). Optional field: an old
   CLI against a new daemon, or the reverse, prints nothing extra.
3. **`peers --json why`**: `BlockedBy::LanCaptured` (`path.rs:1310`) when the LAN tier is refused
   while a capture is active on *this* host — a fact about this host, the way
   `PeerRelaysInstead` is a fact about the peer. `explain` (`path.rs:913`) resolves it in the
   same order `eligible` tests, so the text can never disagree with the verdict.
   **As built (2026-09-03):** the runtime reads the snapshot's captures once per
   `install_peers` walk and tells the monitor, per peer, whether that peer's LAN candidate lies
   inside a captured prefix (`LanCapture::contains_v4` → `PathMonitor::on_lan_capture`). The
   monitor refuses the LAN tier outright — an eligibility gate like #30, no penalty, no Q
   event — so `decide` and the upward prober never propose it and the ~45 futile probes/hour
   stop; the flag clears on the first walk after the capture lifts. Wire label `lan-captured`
   (kebab, like `peer-relays-instead`). Two guards make the gate safe: it is scoped to the
   captured PREFIX (a multi-homed host keeps LAN-dialling neighbours on its other, clear LAN),
   and the detector now exempts a same-LAN **sibling** (a docked laptop whose Wi-Fi and
   Ethernet share one switch: the selected interface holds an address in the prefix, so it
   reaches the LAN — a VPN adapter's tunnel address never does). `meshharbor peers <node>` adds a
   `CAPTURED` hold-down line pointing at `meshharbor status` and the VPN profile.
4. **RC path pill**: `rc:video-info` (`agents/meshharbord/src/peer.rs` ~3043, `video_info_sent`)
   carries an optional `transport_reason` string set by the *agent* from its own capture state;
   the viewer renders `relay · VPN captures the host's LAN`. Optional field — old viewers ignore
   it, old agents omit it.
   **As built (2026-09-04):** the reason is per-viewer, not per-host — the agent names the
   capture only when the session is on a real relay AND one of the viewer's host / prflx
   candidates (read from the peer connection's own stats at `rc:video-info` time) lies inside
   a captured prefix (`lan_capture_reason` → `lan_capture_reason_for`, `peer.rs`). A viewer on
   another network is relayed by the corp NAT and keeps a plain `relay` — the same per-prefix
   scoping as the P2 gate, so the pill never blames the VPN for a relay it did not cause.
   prflx is included because under Check Point the viewer's LAN packets ARRIVE (only our
   replies die), so its LAN address reaches us as a peer-reflexive candidate. Both pumps (libvpx
   and FFmpeg) emit it through the one `video_info_payload` builder; the key is appended last,
   so every pre-P3 viewer parses the message unchanged. A non-`overlay-l3` build has no netstate
   monitor and honestly never names it.
5. Kill switch `overlay_lan_capture_probe` (default on; the probe is a read-only lookup).

## Phases

| phase | scope | kill switch |
|---|---|---|
| P1 | detection + `NetDelta` onset/clear lines + `meshharbor status` line (Windows first; Linux/macOS via the existing `ip route get` / `route get` backends) | `overlay_lan_capture_probe=false` |
| P2 | `BlockedBy::LanCaptured` in `peers --json why` — **implemented 2026-09-03**: LAN-tier eligibility gate per captured prefix + `lan-captured` label + CLI hold-down line + sibling exemption in the detector | same (no captures ⇒ no gate) |
| P3 | `rc:video-info.transport_reason` + the viewer pill — **implemented 2026-09-04**: per-viewer reason from the session's remote candidates × the host's captures; pill suffix `· relay · VPN captures the host's LAN` | same (agent side omits the field) |

## Acceptance criteria

- [x] `meshharbor exec CORPLAP-2 -- meshharbor status` prints the `CAPTURED` line naming `Ethernet 3`
      while its VPN is up; `meshharbor status` on neo16 prints `lan         clear` — first on
      0.4.20 (2026-08-29, #905), re-read on 0.4.61 (2026-09-04): CORPLAP-2
      `CAPTURED — 192.168.68.0/24 leaves via "Ethernet 3" (owned by WLAN)`, neo16 `clear`
- [x] a captured host's `meshharbor peers --json` for a same-LAN peer reads `blocked_by:
      lan-captured` with `penalty: 0` on the LAN tier (CORPLAP-3 on a non-excluded subnet, or
      CORPLAP-2 anywhere) — **0.4.59, 2026-09-04**: CORPLAP-3 → neo16 on `192.168.68.0/24`
- [x] the captured host stops probing the LAN tier: no `probing direct upgrade … tier=Lan`
      lines toward that peer while the capture holds — **0.4.59**: 0 in the 7 min after the
      restart (117 that day before it). **Both halves field-verified 2026-09-24 from the
      three laptops' own logs (0.4.9x, two VPN vendors — see the field log):** 0 LAN probes
      toward neo16 in 16 known-captured intervals of up to 629 min each, and after a
      clear the first LAN probe or direct promotion lands at +0 s to +10 s in 5 of the 7
      clears that needed a resume. The other two took +311 s (neo16 on the LAN, cause
      unexplained) and 18 h (neo16 elsewhere). Of the 9 clears seen, two needed none: the
      LAN carrier survived a 36 s blip, and one had no data before a process restart
- [x] the RC pill on a same-LAN pair whose agent host is captured (`neo16 → CORPLAP-3` at
      home, or `→ CORPLAP-2`) reads `… · relay · VPN captures the host's LAN` — **0.4.61,
      2026-09-04, from Chrome** (raw `rc:video-info` carries `transport_reason: lan-captured`);
      the other half — a viewer from another network sees plain `· relay` — holds by
      construction (no viewer candidate inside the prefix ⇒ no reason) and is locked by the
      unit test, not yet exercised in the field. **2026-09-24:** the same-LAN half held on
      287 real decisions (CORPLAP-1 232, CORPLAP-2 55, 09-09..09-24), each audited against
      its own logged inputs with 0 mismatches. There was still no off-LAN viewer session to
      a captured host in the retained logs, so that half remains by construction
- [x] the daemon log carries ONE onset line and ONE clear line across a VPN connect/disconnect
      cycle on CORPLAP-2 (no per-snapshot spam) — 0.4.61, CORPLAP-2's log 2026-09-03/04: onset
      22:02:39Z, clear 08:32:36Z, onset 08:33:12Z, one delta per transition (each delta is
      echoed by up to three consumers — netstate, the route reconcile, the WS probe — which is
      the same event, not per-snapshot spam); CORPLAP-3 shows the same shape
- [x] no change on hosts without a capture (neo16, rozalina-2, the cluster nodes): status line
      `clear`, `why` unchanged, pill unchanged — 0.4.61, 2026-09-04: neo16, rozalina-2, mars,
      jupiter, zeus all print `lan clear`; neo16's `peers --json` carries no `lan-captured`
      anywhere; the pill on an uncaptured host is by construction unchanged (no captures ⇒
      the agent omits the key)
- [x] `overlay_lan_capture_probe=false` removes the line, the reason and the pill text — 0.4.61,
      2026-09-04 on CORPLAP-3 (see the field log): status `clear`, `why` back to `penalty`
      with no CAPTURED paragraph, pill plain `· relay` with no `transport_reason`; restored
      with `config clear` and everything returned. ⚠️ With the probe OFF the status line read
      `clear`, the same word as a genuinely clear host — fixed 2026-09-06: the daemon now
      honours the wire contract (`lan_captures: None` when the probe is off) and sends
      `lan_capture_probe: false`, which a current CLI prints as `lan probe OFF
      (overlay_lan_capture_probe=false) — no capture verdict …`; an older CLI prints nothing.
      **Field-verified on 0.4.99 (2026-09-23, neo16 probe-off/on cycle — see the field log):**
      exactly that line with `lan_capture_probe: false` and no `lan_captures` key, and
      `lan clear` again after `config clear`

## Open decisions

- ~~Whether a detected capture should also **pause the LAN probe cadence**~~ — **decided
  2026-09-03 (P2): yes.** The verdict is not a heuristic but the OS's own route lookup, i.e. a
  measurement of where the packet WILL go; and the 2026-09-03 pktmon capture on CORPLAP-3
  showed both directions dead at the stack (the peer's initiations dropped by `INET: receive
  inspection`, our replies by `Inspection drop`), so a LAN probe under a capture cannot
  succeed by construction. The one false-positive class found — a same-LAN sibling interface
  on a docked laptop — is exempted in the detector rather than tolerated in the gate. Cost:
  none measured; benefit: ~45 futile probes/hour/pair gone and `why` truthful.

## Out of scope

Bypassing the capture; the relay ceiling; FR-31's encoder work.

Not a bypass, and so in scope as a follow-up (2026-10-11): a LAN interface's **own** prefix row
made unusable underneath it. The row's next hop lies outside the prefix and belongs to no other
interface; no other interface routes the prefix. The lookup then reads "captured" although no VPN
claims the LAN. Repaired by adding the prefix on-link as two halves (`overlay::lan_repair`); any
real capture is still only reported. Mechanics: `docs/overlay-nat-traversal.md` ("When the LAN
tier is gated").

## Field log

| date | build | note |
|---|---|---|
| 2026-08-29 | 0.4.17/0.4.18 (CORPLAP-2), 0.4.16 (neo16) | Motivating case above; `Find-NetRoute -RemoteIPAddress 192.168.68.126` on CORPLAP-2 → `Ethernet 3`, `NextHop 172.30.245.30`, `DestinationPrefix 192.168.68.0/25`; `Get-NetAdapter` names the Check Point adapter. |
| 2026-08-29 | 0.4.20 | **P1 field-verified** on both corp laptops (#905 comment): CORPLAP-2 (Check Point) and CORPLAP-3 (AnyConnect) each print `lan CAPTURED — … leaves via "<VPN adapter>" (owned by WLAN)`; neo16 prints `clear`. |
| 2026-09-03 | 0.4.57 both ends | **The gap P2 closes, measured.** neo16 and CORPLAP-3 on one phone hotspot (`192.168.43.0/24`, outside AnyConnect's fixed split-exclude list `10.0.0.0/24`, `192.168.0.0/23`, `192.168.8.0/24`, `192.168.178.0/24`): CORPLAP-3 `status` says `CAPTURED — 192.168.43.0/24 leaves via "Ethernet 2"`, but its `peers --json why` for neo16 said `lan blocked_by: penalty, fails 5` and neo16 kept probing `192.168.43.10:43664` every ~80 s (`saw_inbound=false`). pktmon on CORPLAP-3: neo16's initiations reach the Wi-Fi NIC and die in tcpip (`INET: receive inspection`); CORPLAP-3's replies die on Tx (`Inspection drop`) — the capture is routing AND filtering, so no probe can ever pass. Same host was `direct lan 9 ms` at home that morning (`192.168.0.0/24`, inside the `/23`). |
| 2026-09-04 | 0.4.59 both ends (#1281 via #1285) | **P2 field-verified.** Sofia home LAN `192.168.68.0/24` (also outside the exclude list; CORPLAP-3 `status`: `CAPTURED — 192.168.68.0/24 leaves via "Ethernet 2"`). Before, on 0.4.58: CORPLAP-3's `why` for neo16 `lan eligible: true, penalty 199.99, fails 10`, 117 `tier=Lan` probes toward neo16 that day (~80 s cadence). After a pinned push (`POST …/agent/{id}/update {"pin":"agent-v0.4.59"}`, installed in 4 min): `lan eligible: false, blocked_by: lan-captured, penalty: 0`; `meshharbor why 100.65.4.2` prints `lan-captured` in the tier table + the CAPTURED paragraph; **0 LAN probes in the 7 min after the 22:38:41Z restart** while 3 other-tier probes ran. neo16 (`lan clear`) unchanged: its `why` for CORPLAP-3 still `penalty`, and it still probes the LAN candidate every ~80 s — the capture is known only to the captured host (a netmap-advertised capture would be a P2b). |
| 2026-09-04 | 0.4.61 (#1289 via #1290) + UI `v20260904-97ac185eecf0` | **P3 field check — NOT passed, and the reason is the viewer, not the agent.** Before (0.4.59 agent, new UI): neo16 → CORPLAP-3 on the captured home LAN, pill `AV1 4:2:0 HW (av1_qsv) · relay · dec HW`, raw `rc:video-info` without `transport_reason`. After (0.4.61): identical — no key, plain `· relay`. Probing the viewer with the peer connection patched: the browser (Edge, Chromium 152) offered **only relay candidates** (eight `94.130.141.74:*` TURN entries, zero host, zero srflx) although the page constructed the connection with the default `iceTransportPolicy`; a bare `RTCPeerConnection` with just a public STUN server gathered **zero candidates** and reported gathering complete. That is Chromium's `disable_non_proxied_udp` WebRTC IP-handling mode (uBlock Origin's "prevent WebRTC from leaking local IP addresses", a privacy extension, or the `WebRtcIPHandling` browser policy): every RC session from that browser is TURN-relayed whatever the target, and the agent structurally never receives a LAN address to match against its captures. The agent side did its part (it offered its LAN host `192.168.68.119`, VPN, overlay, srflx and relay candidates; `meshharbor why` still says `lan-captured`). Second, independent limitation: under AnyConnect the viewer's LAN packets are dropped at the host (pktmon, 09-03), so the prflx path can never form there either — P3 as built can only fire for a Check Point-class capture or a viewer whose mDNS host candidate resolves. Consequences: (1) `lan_capture_reason` now logs its inputs + verdict (next release) so this is readable from the daemon log; (2) **P3b proposed**: attribute on the VIEWER side — the viewer asks its own local daemon over the existing loopback bridge whether the target's LAN prefix is captured for the LAN it sits on, which needs P2b (the capture advertised in the netmap); (3) for the operator: this browser setting is a second, sufficient cause of `· relay` on every RC session from that Edge profile (browser-wide: the same probe yields zero on a neutral origin, and again after the extension reconnected) — worth checking (`edge://webrtc-internals`, uBlock settings, `edge://policy`) before any RC quality work. ⚠️ It is a per-PROFILE property, not "neo16": the same night another extension-driven browser/profile on neo16 offered LAN host candidates and went `· direct` to CORPLAP-1 (agent log `remote_typ=Host remote_addr=192.168.68.126`). So: verify the path per session from the agent's `per-session ICE path detected` line, and re-run this P3 check from a profile that offers host candidates — the agent then receives the viewer's `192.168.68.x` host candidate via signalling and can name the capture without any packet needing to arrive. |
| 2026-09-04 | 0.4.61 + UI `v20260904-97ac185eecf0`, viewer = Chrome 152 | **P3 field-verified.** Same pair, same LAN, same agent build as the failed check — only the viewer changed to a Chrome profile whose bare-STUN probe gathers the full set (host `192.168.68.126` as a plain IP, the overlay addresses, srflx). Pill: `AV1 4:2:0 HW (av1_qsv) · relay · VPN captures the host's LAN · dec HW · FSR`; raw `rc:video-info` ends `"viewers":1,"transport_reason":"lan-captured"`. Under AnyConnect no LAN packet reaches the host, so this proves the candidate arrives by signalling alone. Kept: the relay-only gathering was ONE Edge profile's setting, not the machine; verify the viewer's path per session from the agent's `per-session ICE path detected` line. P3b is no longer needed for correctness (optional, to stop the uncaptured side's LAN probes). |
| 2026-09-04 | 0.4.61 | **Kill-switch cycle + the remaining boxes.** CORPLAP-2 (Check Point, now on the same home LAN): `CAPTURED — 192.168.68.0/24 leaves via "Ethernet 3"`, log onset 22:02:39Z / clear 08:32:36Z / onset 08:33:12Z, one delta per transition. neo16, rozalina-2, mars, jupiter, zeus: `lan clear`, no `lan-captured` anywhere in neo16's `why`. CORPLAP-3: `meshharbor config set overlay_lan_capture_probe false` + a detached one-shot restart (pids 23548,46932 → 2300,40548) ⇒ status `lan clear`, `why` → neo16 LAN tier back on `penalty` with no CAPTURED paragraph, RC pill from Chrome `AV1 4:2:0 HW (av1_qsv) · relay · dec HW · FSR` with no `transport_reason`; `config clear` + restart (→ 26124,32136) ⇒ `CAPTURED`, `lan-captured` and the paragraph all back. Two operational notes: with the probe off the status line says `clear`, indistinguishable from a clear host (wording follow-up); and the automation extension's synthetic Connect click was lost repeatedly after a page reload, while a programmatic `button.click()` connected first time. |
| 2026-09-23 | 0.4.99 (the #1438 fix shipped in `agent-v0.4.76`) | **Probe-off wording field-verified.** neo16 — an uncaptured host, so before the fix the two states read identically: `overlay_lan_capture_probe=false` + `Restart-Service MeshHarbor` from an elevated local shell ⇒ `lan probe OFF (overlay_lan_capture_probe=false) — no capture verdict; why and the RC pill cannot name a VPN capture until it is re-enabled`, wire `"lan_capture_probe": false` and no `lan_captures` key; `config clear` + restart ⇒ `lan clear`, `"lan_captures": []`, `"lan_capture_probe": true`. CORPLAP-3 on 0.4.99 emits `lan_capture_probe: true` (read without touching it; uncaptured at home that day). The mesh was back to 10 direct / 7 relay within a minute of each restart. |
| 2026-09-24 | 0.4.9x–0.4.100, logs 09-09..09-24 on all three laptops | **The two "not exercised" halves, from the fleet's own logs — read-only.** All four hosts sat on one LAN, `192.168.8.0/24`, for most of the window. That subnet is in AnyConnect's exclude list, so CORPLAP-3 is captured only briefly while its VPN connects; Check Point captures CORPLAP-1/-2 whenever their VPN is up, in ~629-min sessions. **P2, stops:** per host, an event stream of capture onset/clear lines, `probing direct upgrade … overlay_ip=100.65.4.2 … tier=Lan` lines and the process-start banner (`DPI awareness configured at process start`). A fresh process logs no initial capture state, so each start ends an interval as unknown. Result: **0 LAN probes toward neo16 inside 16 known-captured intervals** (49–629 min; e.g. CORPLAP-2 09-23 08:53→19:23, 629 min). On 0.4.58 the same kind of host fired 117 a day. ⚠️ A first pass without the process-start reset counted "29 probes inside" one interval that spanned 16 runtime starts — a tracker artefact, not a leak. **P2, resumes:** the first LAN probe or direct promotion after a clear came +0 s (CORPLAP-1 09-11 06:09:26; CORPLAP-2 09-23 19:23:42), +2 s (CORPLAP-2 09-11 06:09:52, promoted with no local probe line, so presumably on neo16's own probe), +3 s (CORPLAP-2 09-12 19:18:35) and +10 s (CORPLAP-3 09-11 07:09:32, AnyConnect). None had a process start in between. A probe in the same second as the clear means the netstate delta carrying the clear triggers the walk directly, not the ~30 s re-upgrade cadence. Two slow cases: CORPLAP-1 09-11 07:04:21 took +311 s with neo16 on the LAN (unexplained; a LAN penalty or the probe cap would fit), and CORPLAP-3 09-11 14:58 took 18 h (neo16 elsewhere). **P3:** every `rc: LAN-capture transport reason` line was pulled (CORPLAP-1 232, CORPLAP-2 55; CORPLAP-3 0, never relayed while captured). Each was re-derived from its own logged `viewer_lan_candidates` and `captured`: **287/287 `lan-captured`, 0 mismatches**, viewers always on `192.168.8.0/24`. The off-LAN half is still unexercised (no such session in the logs). |
| 2026-10-10/11 | 0.4.124 (CORPLAP-3), 0.4.124 (neo16) | **A dead own route read as a capture.** Both on the home Wi-Fi `192.168.8.0/24`, which AnyConnect lists as split-EXCLUDED (`vpncli stats`: Non-Secured Routes `10.0.0.0/24`, `192.168.0.0/23`, `192.168.8.0/24`, `192.168.178.0/24`). CORPLAP-3 nonetheless `CAPTURED — 192.168.8.0/24 leaves via "Ethernet 2"` from 10-10 15:06Z, and every peer relayed; on 10-09 the same pair was `direct · 4 ms` with AnyConnect up and the capture `clear` all day. The Wi-Fi's own row: `192.168.8.0/24 if 26 nh 192.168.0.1 rm 0 proto=Local type=3` (a stack DIRECT route with a gateway from another network; neighbour `192.168.0.1` = `Incomplete`). `Find-NetRoute 192.168.8.115` → `0.0.0.0/0 via Ethernet 2`; `ping` → `General failure`. AnyConnect's event log "Routing table - Original" (22:02:55Z) already carried the stale row. Live repair, on the operator's go: `192.168.8.0/25` + `.128/25` on-link via the Wi-Fi (active store) ⇒ `Find-NetRoute` → `/25 via WLAN`, ping 3/3 at 1–2 ms, AnyConnect stayed `Connected`, and within a minute `meshharbor why 100.65.4.2` read `carrier direct via 192.168.8.115:61971, tier lan`, neo16 `direct · 13 ms`. Built into the agent as `overlay::lan_repair` (`overlay_lan_route_repair`, default on). |
| 2026-10-11 | 0.4.125–0.4.127 (CORPLAP-3), 0.4.126 (neo16) | **The agent repair, and its kill switch, cycled on the same laptop.** On: with both halves deleted by hand, the agent re-added them in **761 ms** with its WARN line (`prefix=192.168.8.0/24 interface=WLAN dead_next_hop=192.168.0.1`), and the pair stayed `direct … tier lan`. Off (`overlay_lan_route_repair=false` + a restart): the first sample, 1.4 s after the worker started, removed both halves with `why=Disabled`. The dead `/24` was again the only LAN route (`Find-NetRoute` → `0.0.0.0/0 via Ethernet 2`), neo16's LAN ping to CORPLAP-3 went from 3/3 to 0/3, and neo16's `why` read the `192.168.8.112` path at 100 % loss with `lan` ineligible and the carrier on `relay:derp`. Back on (`config clear` + `meshharbor restart`): the first sample re-added both halves (the WARN line, ~1 s after the worker started), and the pair was `direct · 5 ms` 40 s later. It stayed direct through the auto-update to 0.4.127 that followed. The first restart, a SYSTEM task running `Restart-Service`, left the service stopped for 10 min 24 s: that is #2010. |
