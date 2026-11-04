# Media over QUIC (MoQ) for Roomler remote desktop — evaluation + deferred plan

> **Status: evaluated 2026-06-04, DEFERRED — not being implemented now.** Captured for later reference. Verdict: do **not** adopt MoQ for the interactive control path; the only defensible use is a future opt-in multi-viewer broadcast, gated on a Phase-0 spike + a real customer need.

## Context

The team shipped a QUIC (quinn) transport for the **roomler** CLI (native-to-native TCP forwarder). The follow-on question: should the **remote-desktop** subsystem (TeamViewer-style screen + input control) also adopt **MoQ (Media over QUIC)**?

This doc is the answer ("research + evaluate MoQ + weigh pros/cons + decide if it benefits remote desktop + give an implementation plan"). It is grounded in (a) a full code map of the current data plane, (b) the IETF/library/browser state of MoQ as of June 2026, (c) a peer-reviewed QUIC-vs-WebRTC remote-rendering benchmark, and (d) an adversarial stress-test of the conclusion.

### How remote desktop works today (verified)
- **P2P WebRTC** (webrtc-rs): the controlled-host **agent is the answerer**, the **browser controller is the offerer**; media flows agent↔browser directly, **TURN-relayed only when NAT requires** — and TURN relays *opaque DTLS*, so **the server never sees pixels**. (`agents/meshharbord/src/peer.rs`; `crates/remote_control/src/turn_creds.rs`.)
- Three video sub-paths: WebRTC **video track** (RTP/SRTP, H.264/HEVC/AV1, `peer.rs:852-1690`); **HEVC-over-DataChannel** and **VP9-444-over-DataChannel** (`peer.rs:895-994`) — both send raw frames over the `"video-bytes"` SCTP DataChannel with a **13-byte length header** (`frame_video_bytes`, `peer.rs:1714`), 16 KiB chunks, AIMD on `dc.buffered_amount`, keyframe-on-open gating.
- The two DC paths **decode in the browser via WebCodecs onto a canvas** (`ui/src/workers/rc-vp9-444-worker.ts`, `rc-hevc-worker.ts`) — already bypassing `<video>`'s jitter buffer (present-ASAP). Input is JSON over an `"input"` DataChannel (`peer.rs:2922-3008`, enigo). Transport is chosen via `AgentCaps.transports` + `ClientMsg::SessionRequest{preferred_transport}` (`encode/caps.rs:142-232`, `signaling.rs:250`).

## Evaluation — pros / cons (the "is there a benefit?" answer)

**MoQ is purpose-built for client-server/relay *distribution at scale*, not P2P interactive.** Browsers cannot do P2P-QUIC (P2P-WebTransport/ICE-QUIC is an unshipped W3C draft), so MoQ for remote desktop *forces* a relay: agent (publisher) → **relay** → browser (subscriber). That single fact drives the evaluation.

| Dimension | MoQ for remote desktop | Verdict |
|---|---|---|
| **Interactive latency** | Relay-mandated. Benchmark (arXiv 2505.22132, 1080p): **MoQ 559 ms vs WebRTC-P2P 288 ms** ("≈100% higher, relay architecture"). The *P2P* QUIC variant RoQ won (215 ms) — but RoQ is **unreachable from a browser**. | ❌ Disqualifying for mouse→pixel control |
| **Corp NAT / UDP-block reach** | WebTransport is HTTP/3 = **UDP-only, no TCP/443 fallback**. Today's WebRTC has **TURNS-over-TCP/443** for UDP-blocked corp nets. | ❌ Strictly *worse* reach |
| **"Server never sees pixels"** | A MoQ relay sees object payloads unless `moq-secure-objects` (SFrame E2E) — a WG **draft, pre-stable, DIY key mgmt**. | ❌ Privacy regression (mitigable only with immature E2E) |
| **WebCodecs / no-jitter-buffer win** | This is MoQ's headline interactive argument — **already banked** by the DC paths (WebCodecs→canvas, present-ASAP). | ⚪ No new gain |
| **Maturity** | moq-transport **draft-17** (not RFC); secure-objects draft; proponents say "years to WebRTC parity." Our WebRTC+DC path was just hardened (rc.94–106). | ❌ Moving target vs proven |
| **quinn reuse (from tunnel)** | The browser side is **WebTransport, not quinn**; the tunnel's 8 MiB-window *throughput* tune is the opposite of what interactive media wants. | ⚪ Red herring for the browser path |
| **Connection setup** | MoQ/QUIC ~532 ms vs WebRTC ~1421 ms. One-time; dominated by our own WS/signaling anyway; can't justify paying 2× steady-state latency. | ⚪ Marginal |
| **Multi-viewer fan-out** | `max_simultaneous_sessions: 1` today (`encode/caps.rs:281`); N WebRTC viewers = N encodes + N congestion loops on the controlled host, or build an SFU. MoQ pub/sub = **encode once, relay fans out to K**. | ✅ The *one* real fit (latency-tolerant spectators) |

**Adversarial check:** a dedicated devil's-advocate pass tried six ways to break the verdict (agent-as-WebTransport-server; video-MoQ/input-WebRTC hybrid; browser RoQ; multi-viewer; faster setup; quinn reuse) — **none broke it**; several reinforced it (UDP-only reach; RoQ-not-browser-reachable). The verdict is sound.

## Recommendation

1. **Leave the 1:1 interactive control path on WebRTC. Do not adopt MoQ there.** The relay hop ≈doubles latency, reach gets worse on corp nets, and the WebCodecs win is already captured.
2. **The only MoQ-shaped opportunity is an opt-in, view-only multi-viewer broadcast** (supervised support / training / "share read-only to N watchers"). It is a *new feature*, not a transport swap, and it is **worth only a cheap Phase-0 spike — built out solely on a GO result AND a concrete multi-viewer customer need.**

---

## Implementation plan (the narrow, gated path — for if/when this is revisited)

Everything is **feature-flagged** (`--features moq-broadcast` + `ROOMLERD_MOQ=1`) so default builds advertise nothing and no field session can negotiate onto it — same discipline as `vp9-444` / `ffmpeg-encoder`. The 1:1 WebRTC control path is **never touched**.

### Phase 0 — hard-gate spike (the only thing worth doing first; cheap, reversible, throwaway)
**Build (minimal):**
- **Agent probe** (`roomlerd moq-probe`, behind the feature): reuse `capture::open_default` + `encode::open_for_codec` (`encode/mod.rs:349`); wrap each frame with the **existing** `frame_video_bytes` 13-byte header verbatim (`peer.rs:1714`); publish via the kixelated **`moq-lite`** + **`web-transport`** Rust crates (native QUIC) — map one keyframe-led GOP = one MoQ *group*, each frame = one *object*.
- **Relay**: run kixelated **`moq-relay` as one container on an existing coturn host** (we already operate + monitor these). No new cloud account.
- **Throwaway browser subscriber** (a static page / hidden route, *not* wired into `RemoteControl.vue`): open a `WebTransport` to the relay, subscribe, and `postMessage({type:'chunk', bytes})` to the **unmodified** `rc-vp9-444-worker.ts` / `rc-hevc-worker.ts` (the existing transport-agnostic handoff in `useRemoteControl.ts:~1850`). If frames paint, subscriber-reuse is proven.

**Measure (on the Iris-Xe and RTX-5090 field boxes):**
1. **Glass-to-glass p50/p95**, agent→relay→browser, vs the WebRTC-P2P baseline (instrument the worker using the capture `ts_us` already in the header).
2. **Fan-out** K ∈ {1, 5, 20, 50}: agent CPU + egress must stay **flat** as K grows (the whole point).
3. **Agent CPU delta** to run the publisher *concurrently with a live WebRTC control session* (must be near-free on top of an encode we already do).
4. **`moq-secure-objects` feasibility** (2-day timebox): can we SFrame-wrap on publish + unwrap in the worker with sane key distribution over our authenticated signaling, or do we accept a trusted relay?
5. **Slow-viewer isolation**: one degraded subscriber must not affect others.

**GO / NO-GO bars — NO-GO (kill) if ANY:**
- Publisher adds **> ~15 % of one core** at 1080p30 on top of the existing encode (i.e. not truly "encode once").
- Glass-to-glass **p95 > 1500 ms**.
- Fan-out does **not** hold agent CPU/egress flat as K grows (then MoQ bought nothing over N×WebRTC — just raise `max_simultaneous_sessions` to 2–3 and stop).
- `moq-lite`/`web-transport` **don't build clean against `quinn 0.11 + ring`** (the deliberate no-C-build stance, `tunnel-core/Cargo.toml`) and vendoring exceeds ~3 days.

### Phase 1 — broadcast feature (only on GO **and** a real multi-viewer need)
- **Publisher module** in `agents/meshharbord`: clone `media_pump_vp9_444_dc` (`peer.rs:1743`) into `media_pump_moq` — identical capture/keyframe/AIMD/scene-change logic, only the *sink* differs (publish object instead of `dc.send`). Reuse `frame_video_bytes` **verbatim**.
- **Wire types** `rc:broadcast.*` in `crates/remote_control/src/signaling.rs` (mirror `SessionRequest`/`Request` `signaling.rs:250/533` + the tunnel additions): `BroadcastStart` → `BroadcastRequest`(agent, via `Hub::send_to_agent`) → `BroadcastReady{relay_url, path}`; `BroadcastJoin` → server tenant/consent gate (mirror cross-tenant check `api/src/ws/tunnel.rs:394`) → `BroadcastJoinGranted{relay_url, path, [sframe_key]}`. **Broadcast triggers the existing consent broker** (a broadcast is a stronger consent event than a 1:1 view).
- **Caps + version gate**: probe-gated `"moq-broadcast"` in `AgentCaps.transports` (`encode/caps.rs`, default build omits it — lock with a caps regression test); add `MIN_MOQ_AGENT_RC` + `agent_supports_moq()` next to `agent_supports_quic` (`crates/tunnel-core/src/transport/mod.rs:38-84`) so the server won't set up a broadcast for an agent too old to publish.
- **Relay**: self-hosted `moq-relay` co-located with coturn; hand out the relay address like TURN creds (template: `ice_servers_for`, `turn_creds.rs:54`).
- **Browser observer**: a new `startMoqObserverPath()` in `useRemoteControl.ts` (sibling to `startVp9_444Path`) that opens WebTransport + subscribes and forwards bytes to the **unmodified** worker; a lightweight observer route (canvas only, **no input/clipboard/file** wiring).
- **Alongside WebRTC**: broadcast is a **separate session kind** (its own agent-side peer map + teardown, mirroring `tunnel_quic_peers`), runnable simultaneously with a 1:1 control session — it is **not** a value in the control session's `preferred_transport`.
- **Privacy posture (decide before build):** **(A) trusted self-hosted relay (default)** — the relay (our own infra) can see broadcast pixels; document it loudly in the consent UI + `docs/remote-control.md` as a deliberate, opt-in change from the 1:1 "server never sees pixels" posture. **(B) E2E secure-objects** — only if relay-blindness is a hard requirement.

### Phase 2 — E2E (only if relay-blindness is demanded)
- `moq-secure-objects` SFrame wrap on publish + unwrap in the worker; distribute the per-track key via the already-authenticated, tenant-gated signaling (`BroadcastJoinGranted.sframe_key`). Re-gate on draft stability. **Do not** attempt MLS group-keying for v1.

## Honest risks / when NOT to build at all
- **Pixel-trust regression (highest):** default posture (A) lets a Roomler-operated relay see broadcast pixels — may be a non-starter for a security-sensitive product regardless of engineering. Decide up front.
- **secure-objects immaturity** + DIY key distribution (if posture B is required, may itself be NO-GO).
- **quinn/rustls version war** with the kixelated crates (would threaten the no-C-build stance) — a Phase-0 kill condition.
- **New stateful relay** ops/DoS surface on the coturn hosts.
- **"Encode once" may not hold** if the 1:1 controller negotiated a codec observers can't decode (→ double encode). Phase-0 measure #3 catches it.
- **Scope creep**: hold the line — observers are render-only; "can a watcher take control?" is a different, harder feature.
- **DO NOT BUILD** (stop after Phase 0, or skip it) if: no customer is asking for observers; relay-blindness is required and secure-objects keys can't be made sane; or Phase-0 shows the publisher isn't free / fan-out doesn't hold.

## Critical files (for a future implementation)
- `agents/meshharbord/src/peer.rs` — publisher source to clone (`media_pump_vp9_444_dc:1634`, `frame_video_bytes:1605`, dispatch `:885-987`).
- `agents/meshharbord/src/signaling.rs` — agent-side `rc:broadcast.*` handling + a new broadcast-peer map (mirror the `TunnelQuicSetup` arm + `close_all_tunnel_quic_peers` teardown).
- `crates/remote_control/src/signaling.rs` — new `rc:broadcast.*` `ClientMsg`/`ServerMsg` wire types (mirror `SessionRequest`/`Request` + tunnel additions).
- `crates/tunnel-core/src/transport/mod.rs` — `MIN_MOQ_AGENT_RC` + `agent_supports_moq()` next to `agent_supports_quic`.
- `agents/meshharbord/src/encode/caps.rs` — probe-gated `"moq-broadcast"` cap + a default-build-omits-it test.
- `ui/src/composables/useRemoteControl.ts` — `startMoqObserverPath()` (mirror `startVp9_444Path`); reuse the worker handoff verbatim. `ui/src/workers/rc-vp9-444-worker.ts` / `rc-hevc-worker.ts` — **unchanged**.
- `crates/api/src/ws/tunnel.rs` — server-side auth-boundary + version-gate pattern to copy. `crates/remote_control/src/turn_creds.rs` — `ice_servers_for` template for handing out the relay address.
- New deps (Phase 0): `moq-lite`, `web-transport` (Rust, kixelated/moq-dev); `moq-relay` container. New build feature `moq-broadcast`.

## Verification (Phase 0)
Run `roomlerd moq-probe` on a field box, `moq-relay` on a coturn host, open the throwaway subscriber page in 1 + K browser tabs. Confirm frames paint via the unmodified worker (subscriber-reuse), then collect the five measurements above and check them against the GO/NO-GO bars. Everything is behind the `moq-broadcast` feature + `ROOMLERD_MOQ=1`; deleting the feature is a clean revert. No change to the WebRTC control path is shipped at any point in Phase 0.

## Out of scope
- Replacing the 1:1 WebRTC control transport (rejected — see Evaluation).
- A native (non-browser) controller running RoQ/P2P-QUIC (a far larger, separate project).
- MLS-based MoQ group encryption (`moq-e2ee-mls`).

## Sources
- [draft-ietf-moq-transport-17](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/) · [draft-ietf-moq-secure-objects](https://datatracker.ietf.org/doc/draft-ietf-moq-secure-objects/)
- [QUIC-vs-WebRTC remote-rendering benchmark (arXiv 2505.22132)](https://arxiv.org/abs/2505.22132) — MoQ 559 / WebRTC 288 / RoQ 215 ms @1080p
- [moq.dev "Replacing WebRTC"](https://moq.dev/blog/replacing-webrtc/) · [Cloudflare MoQ](https://blog.cloudflare.com/moq/) · [WebTransport is now Baseline](https://webrtc.ventures/2026/04/webtransport-is-now-baseline-what-it-means-for-real-time-media/)
- [kixelated/moq (moq-lite + hang, quinn)](https://github.com/kixelated/moq) · [moq-dev/web-transport](https://github.com/moq-dev/web-transport)
