# FR-64 — Remote desktop never rides the overlay

**Issue:** [#1244](https://github.com/jk-zhang-meta/MeshHarbor/issues/1244) · **Status:** proposed · **Plan:** `immutable-doodling-neumann` (approved 2026-09-02)

**Parent/siblings:** FR-59 (the regression that motivated the arc). This is one of three FRs from that plan (FR-62 encoder apply path, FR-63 the controller, FR-64 the data path).

## Goal

A remote-desktop session never has its ICE pair nominated on an **overlay-adapter address**. On 2026-09-02 a corp laptop's session nominated `udp4 host 100.65.0.5 ↔ 100.65.0.6`, so the video rode WebRTC → overlay TUN → WireGuard → DERP over TLS → the corporate VPN, shed by our own DERP mux (100 ms queue-age bound), at 20–400 kbps with seconds of paint age — while the same host's native TURN pair would have carried it. The rc.319 interface filter never worked on Windows (webrtc-util reports every adapter with name `""`) or macOS (`utunN`), srflx and remote candidates are never filtered, and host↔host type-preference wins whenever the overlay pair connects. Decision (operator, 2026-09-02, after the trade-off analysis in the spec): **never for RC** — WebRTC is already end-to-end encrypted, the overlay layer buys RC nothing but a hostile floor.

Same root, second symptom: **#1237** — on multi-org hosts the two org runtimes evict each other's derived-ULA `/96` route every guard wave ("any interface other than ours"), a ~100/min forced-rekey storm on every peer; and the same missing notion of "own adapters" silently withholds the primary's block floor.

## Key design

- **C1** (kill switch `overlay_ice_candidates`, ON = today): own-adapter address `ip_filter` at gather (`SettingEngine::set_ip_filter`, addresses on our own adapters, never a CIDR — an ISP CGNAT address on the physical NIC is kept); the srflx mapped address filtered in the already-forked webrtc-ice (`webrtc-ice.patch`) plus a belt at the signaling hop; remote non-relay candidates equal to a LocalAPI `peers()` overlay IP or our own dropped in `add_remote_candidate` (relay-typed exempt, so the loopback TURN stays). PathClass-lite in the ICE-path log line and in the FR-35 memory key (`"{ip}|{class}"`); an additive `carrier` field on the LocalAPI peer entry.
- **C2** (#1237, first): an own-adapter registry in tunnel-core (`OWN_TUNS` registered in `SystemTun::up_with`, freed in `Drop`), exempted by every eviction helper and by `non_overlay_v4_addrs`; nobody asserts the whole `/96` — `defend_self_route` defends the connected block's derived prefix at `v6_onlink_plen` (byte-identical for single-org); a WARN when two orgs' blocks overlap. Switches `overlay_sibling_exempt`, `overlay_v6_defend_narrow`.

## Acceptance criteria

- [ ] AC1 — CORPLAP-1 (multi-org, VPN on): `ICE: gathered local candidate` shows no `100.6x.`/`fd72:` host or srflx; `per-session ICE path detected` shows a relay/srflx pair outside the overlay ranges; no `overlay carrier under the nominated pair is not direct` line.
- [ ] AC2 — CORPLAP-3 on the LAN: the native `192.168.0.x` pair, p50 ≤ 50 ms.
- [ ] AC3 — `overlay_ice_candidates = true` brings the old `100.65.0.5 ↔ 100.65.0.6` pair back.
- [ ] AC4 — 24 h on neo16 / CORPLAP-1 / CORPLAP-3: sibling evictions **0** (today 718/day), forced-revalidation pokes at idle baseline (today ~100/min), no withheld block floor on the primary.
- [ ] AC5 — `docs/multi-org.md` and `docs/overlay-nat-traversal.md` state the rule (the former's "ICE never gathers on meshharbor-*" is true only on Linux today).

## Open decisions

- Proxy-only egress (443 only) loses RC under "never": a `turns:` listener on 443 on coturn, or the loopback-TURN opt-in.
- Whether an ICE restart on a mid-session carrier change is worth building later (not needed under "never").

## Out of scope

- The rate controller (FR-63) and the encoder apply path (FR-62); SSH/tunnels keep the overlay.

## Related

#1237, FR-59 #1163, FR-33 (VPN LAN capture), FR-19 #805 (org relay), FR-35, FR-62, FR-63.
