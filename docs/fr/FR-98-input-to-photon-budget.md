# FR-98: Input-to-photon budget — make "under 50 ms" true on a direct path, and prove it

**Issue:** [#2090](https://github.com/gjovanov/roomler-ai/issues/2090) · **Status:** proposed 2026-10-13 — spec
and claim; P1 (C1, the slot-first gate) built behind its switch, field A/B owed; P5 (C6) field-measured
2026-10-16 and on by default after it (§9) · **Owner:** the agent's capture and encode path, the viewer's input and paint path · **Anchors:**
master `4fc8ea7bb` · **Program:** [StarDesk teardown](../plans/stardesk-teardown-program.md), wave 1 ·
**Builds on:** [FR-16](FR-16-rc-quality-benchmark.md) (L0 and L4, the instrument this FR is accepted on),
[FR-1](FR-1-remote-desktop-drag-smoothness.md), [FR-70](FR-70-media-pipeline-leaves-the-runtime.md),
[FR-74](FR-74-text-clarity-on-direct-paths.md)

## 1. Goal

A controller's input reaches the host and comes back as painted pixels fast enough that a person cannot
tell the machine is remote. Measure it **input to photon**, as a distribution, and cut it stage by stage.

StarDesk advertises "under 50 ms" against "200–300 ms" for its competitors. We cannot say whether
Roomler beats that, matches it or loses to it, because nothing in the product measures it (§2). FR-16's
L4 builds the measurement. This FR spends it.

The target is set from the L4 baseline, not before it. The expected shape is a direct LAN pair at 60 fps
with p50 ≤ 50 ms and p95 ≤ 80 ms, and no regression on a relay pair.

## 2. Evidence (master `4fc8ea7bb`)

| What | Where | Consequence |
|---|---|---|
| The only clock probe measures **paint age**, not input to photon | `rc:clock` → `rc:clock.echo`: `ui/src/composables/useRemoteControl.ts` L5509, `agents/meshharbord/src/peer.rs` L3036, L8874; consumed in `rc:decodestat` L8739 | Age starts at capture. Input coalescing, injection, the host's own compositor and the capture gate are all invisible to it |
| The §12 latency budget has never been measured | `docs/remote-control.md` §12 (L970–981): ~50 ms LAN at 60 Hz, "up to 16 ms" for injection → next capture | A table of targets, not of numbers |
| Direct-path paint age is already small | FR-74's Regal-Elena-PZ cell (2026-09-10): 1920×1080 HEVC, direct, 6–11 ms | On direct paths the sender and the wire are **not** where the time goes |
| WGC is event-driven, but a minimum-period sleep runs **before** the slot is checked | `agents/meshharbord/src/capture/wgc_backend.rs` L293–297 (sleep), L302 (slot), L309–311 (`FrameArrived` notify); period in whole ms at L259 | A frame already waiting can pay up to one period (16.7 ms at 60 fps). `1000/144` truncates to 6 ms |
| The same gate in the scrap backend | `capture/scrap_backend.rs` L352, L505–509 | Same cost on macOS and X11 |
| The pump deliberately has no second pacer | `peer.rs` L5340–5350 (the rc.92/93 lesson), once-per-open config L5353–5391 | Pacing changes belong in the capture backend, not the pump |
| An idle NVIDIA GPU encodes at ~20 ms/frame until its clocks ramp | `agents/meshharbord/src/gpu_clock.rs` L3–12; the pin is **default OFF** (`MESHHARBORD_GPU_CLOCK_PIN`, L16) | The first seconds of every session, and every light-motion session, pay it |
| Mouse moves are coalesced to one per 8 ms | `useRemoteControl.ts` L5552 (`INPUT_MOVE_GAP_MS`), fed by `pointerrawupdate` (L10075–10113) | Up to 8 ms before an input leaves the browser |
| The cursor poller runs at 125 Hz | `peer.rs` L9019 (`interval(8 ms)`) | Up to 8 ms before a cursor shape or position change is seen |
| NVENC low-latency settings: `delay=0` shipped; preset and tune are knobs | `encode/ffmpeg/encoder.rs` L329–330 (`p4` / `ll` defaults, `MESHHARBORD_FFMPEG_PRESET` / `_TUNE` at L281–282), L362–363 (`delay=0`, rc.130) | Only `p1`–`p3` and `ull` are untested |
| The RTP fallback never sends the `playout-delay` header extension | the vendored `rtp` crate has `PlayoutDelayExtension`; the agent writes with `write_sample` (`peer.rs` L2913), not `write_sample_with_extensions` (`crates/vendored/webrtc/src/track/track_local/track_local_static_sample.rs` L80) | Chrome's jitter buffer is not told to render ASAP on that path |
| That path is the fallback, not the default | `pickAutoTransport` (`useRemoteControl.ts` L2787) ranks every data-channel cell above the H.264 track; the `<video>` render path is the default for the track (L1897–1906) | Only agents or browsers without a DC cell take it. It carries the open Known Issue "Chrome's ~80 ms jitter-buffer floor" |

## 3. Where the time goes (to be replaced by L4's numbers)

At 60 Hz on both ends, a direct pair today, before any cut:

```mermaid
flowchart LR
  A["input event<br/>(browser)"] -->|"0–8 ms coalescer"| B["input DC"]
  B -->|"wire, ~1 ms LAN"| C["injection<br/>(SendInput / uinput)"]
  C -->|"0–16.7 ms<br/>host compositor vsync"| D["frame composed"]
  D -->|"0–16.7 ms capture gate<br/>(sleep before slot)"| E["captured"]
  E -->|"4–8 ms encode<br/>(~20 ms GPU idle P-state)"| F["encoded"]
  F -->|"DC + wire"| G["decoded<br/>(3–5 ms)"]
  G -->|"paint in output callback"| H["canvas"]
  H -->|"0–16.7 ms<br/>viewer vsync"| I["photon"]
```

The sum lands at roughly 45–70 ms. **The two vsyncs and the capture gate dominate**, followed by the GPU's
idle P-state on NVENC hosts. A higher refresh rate shrinks both vsyncs. That is the job of the wave-2
high-refresh FR, not this one.

## 4. Design: cuts, each one attributed by L4

Every cut is a separate change behind its own switch, A/B'd on the **same cells** with L4. A cut that
does not move L4 is reverted, not kept "for later". FR-79's lesson applies: knobs that move no measurement
are not a result.

| # | Cut | Anchor | Switch (default for one release) |
|---|---|---|---|
| C1 | **Slot-first capture gate.** Check the slot first; sleep only when the source is outrunning the target; period in µs | `wgc_backend.rs` L259, L293–302; `scrap_backend.rs` L352, L505–509 | `MESHHARBORD_CAPTURE_GATE` = `slot_first` / `legacy` (legacy) |
| C2 | **GPU clock pin on for NVENC sessions** | `gpu_clock.rs` | `MESHHARBORD_GPU_CLOCK_PIN` (unchanged); the flip is a default change after the A/B |
| C3 | **Input gap 8 → 4 ms** (0 and 2 measured too) | `useRemoteControl.ts` L5552 | viewer knob `roomler-rc-input-gap` |
| C4 | **Cursor poller 8 → 4 ms**, or event-driven where the OS offers it | `peer.rs` L9019 | `MESHHARBORD_CURSOR_POLL_MS` (2–50 ms) |
| C5 | **NVENC preset `p1`–`p3` × tune `ull`** | `encoder.rs` L329–330 | the existing `MESHHARBORD_FFMPEG_PRESET` / `_TUNE`; bake the winner per backend |
| C6 | **`playout-delay` min = max = 0 on the RTP fallback track.** `register_header_extension` on the media engine, `write_sample_with_extensions`, and the SDP echo checked | `peer.rs` L2913 | `MESHHARBORD_RTP_PLAYOUT_DELAY_ZERO` (off for 0.4.134–0.4.138; on after P5's A/B, `=0` turns it off) |

⚠️ **No new per-frame reads in the pump.** FR-70 M3 makes the media thread read an immutable plan. Until
then, every switch above is read once per open (`peer.rs` L5353–5391), never per frame.

### 4.1 C1 before any measurement: what the slot-first gate is expected to buy

Working the legacy gate through on paper, before L4 exists, narrows what C1 can claim:

- **The legacy gate only bites when a frame is already in the slot**, that is, when it landed while the
  pump was encoding the previous one. A frame that lands after the pump has started waiting is taken at
  once, on either gate.
- **Its period truncates to whole milliseconds**, so its cadence runs slightly faster than a source at the
  target rate: 33 ms against 33.3 at 30 fps, 16 ms against 16.7 at 60. The phase between the two clocks
  slides about 0.3 ms (30 fps) or 0.7 ms (60 fps) a frame, a backlog drains on its own, and once the pump
  is the one waiting the legacy gate costs nothing either (`gate.rs`,
  `a_truncated_legacy_period_drifts_out_of_the_wait_on_its_own`).
- **It costs at an exact period** (25, 40, 50 or 125 fps), where the phase can lock, and **for the frames
  after a slow encode**. A real sleep overshoots, so even a "locked" phase drifts, and the wait saws through
  the period, averaging about half of it.
- **The prediction:** C1's steady-state gain on today's 30 and 60 fps targets is small, and L4 has to show
  otherwise for it to stay on (§4's rule). Its µs period matters more to the high-refresh FR, where
  `1000/144` truncates to 6 ms and caps at 166 fps.
- **Scope:** the WGC backend only. `scrap` and DRM grab on request, so their sleep sets the sampling
  cadence instead of stranding a frame that has already arrived. They keep the legacy gate.

⚠️ **Intra-refresh is not on this list.** It spreads an IDR's bytes over frames, which is a loss-recovery
property. It belongs to [FR-17](FR-17-partial-reliability-video.md) stage C, whose spec already says it
"stops being optional" there.

### 4.2 What P5's field cells found besides C6

C6's A/B (§9, 2026-10-16) ran the RTP track against a vmtest guest and turned up two faults on that track
that no cut in §4 covers. Each is its own issue, because each is a one-PR fix:

| Fault | Where (master `69ec6ad67`) | Measured | Issue |
|---|---|---|---|
| A Windows host with no H.264 hardware encodes the track on Microsoft's software MFT, the cascade's last Media Foundation fallback, and logs it as `mf-h264 (hardware)` | `encode/mf/activate.rs` L279, `encode/mod.rs` L1241 | L4 p50 ~850 ms and a quarter of probes unanswered in 2 s, against 37 ms on OpenH264 on the same guest. C6 empties Chrome's buffer and leaves L4 where it was | [#2283](https://github.com/gjovanov/roomler-ai/issues/2283) |
| The track's timestamps run one frame behind: a sample's `duration` is the gap *before* it, and the packetizer stamps a sample before advancing by it | `peer.rs` L3055–3075; `crates/vendored/rtp/src/packetizer/mod.rs` L127, L135 | The lag is measured: L0's `cadence` cell (§9) read each frame's RTP step 158.8 ms (p50) off its arrival step before the fix and 0.9 ms after. Its share of Chrome's hold (193 ms on average with C6 off, growing to 326, against Chrome's own ~53 ms target) is suspected, not proven, until the field A/B on a release carrying the fix | [#2284](https://github.com/gjovanov/roomler-ai/issues/2284) |

⚠️ **C6 only helps a browser that offers `playout-delay`.** Chrome does. Whether Firefox or Safari do has not
been checked, and they are the browsers the RTP track mostly serves, because Chrome and Edge take a
DataChannel cell wherever one exists. A browser without the extension is left with whatever #2284 costs it.

## 5. Phases

| P | Scope | Kill switch | Status |
|---|---|---|---|
| P0 | This spec and the claim. The **baseline**: L4 on the cells of §9, recorded before any cut | docs only | this PR |
| P1 | C1, the slot-first gate | `MESHHARBORD_CAPTURE_GATE` unset or `legacy` | **built**: `capture/gate.rs` (the token bucket, unit-tested on synthetic timelines); the WGC backend behind the switch, legacy branch unchanged; L0's `gate_lgcy` / `gate_slot` cells (§9). Field A/B owed |
| P2 | C2, the GPU clock pin A/B, then the default decision | `MESHHARBORD_GPU_CLOCK_PIN=0` | — |
| P3 | C3 + C4, the input and cursor cadences | `roomler-rc-input-gap` unset (8 ms); `MESHHARBORD_CURSOR_POLL_MS` unset (8 ms) | **knobs built**, defaults unchanged: `storedInputGapMs` (0–16 ms, read once per viewer) and `capture::cursor::poll_interval` (2–50 ms, read once per session). The 0/2/4 ms A/B on L4 is owed, and open decision 3 waits on it |
| P4 | C5, the NVENC preset/tune A/B, baked per backend | `MESHHARBORD_FFMPEG_PRESET` / `_TUNE` | — |
| P5 | C6, `playout-delay` on the RTP fallback, and the Known-Issue verdict | `MESHHARBORD_RTP_PLAYOUT_DELAY_ZERO=0` | **built**, and **on by default** after its A/B (`agents/meshharbord/src/rtp_playout.rs`; off for 0.4.134–0.4.138). Off, the extension is not registered, so the answer and every packet stay byte-identical. On, it is negotiated wherever the browser offers it and written on every video packet. L0's `playout0` cell (the switch unset) proves the default on the wire; every other cell forces it off and proves the off state. **Field-measured 2026-10-16** (§9): on the RTP track with OpenH264, Chrome's jitter buffer 193 → 0.1 ms and L4 p50 78–362 → 35–40 ms. **Field-checked on agent 0.4.139** (§9): with no switch set, the extension is negotiated on every session, Chrome's buffer is 0.1 ms and L4 p50 37 ms (median of 12 batches); the Known Issue is closed (AC6) |
| P6 | Docs, and the final field table | — | — |

## 6. Acceptance criteria

- [ ] **AC1:** the P0 baseline exists: L4 p50/p95/p99 on every cell of §9, on the deployed build, before any
  cut ships. This is the red record every later AC is read against.
- [ ] **AC2:** each cut C1–C6 has an L4 A/B on the same cells, one switch flipped. A cut that does not move
  p50 or p95 beyond the cell's run-to-run spread is reverted, and the revert is recorded.
- [ ] **AC3:** C1 moves L0's capture→decode p50 by at least **a quarter** of a frame period in CI (gate on
  vs off). It also moves L4 on a direct field pair. *(Amended 2026-10-13, before any measurement: the spec
  first said half a period. A real sleep overshoots, so the legacy wait saws through the period instead of
  locking, and half a period is the expected difference itself, not a bound with room. §4.1 has the
  reasoning.)* L0 measures it on an emulated source at 25 fps, whose 40 ms period is exact, with frames
  landing three quarters of a period ahead of the legacy cadence. Only there can L0 make the legacy gate
  pay at all (§4.1).
- [ ] **AC4:** a direct LAN pair at 60 fps meets the target fixed at P0 (expected: p50 ≤ 50 ms, p95 ≤ 80 ms).
  It is measured by L4, and cross-checked once against a 240 fps camera.
- [ ] **AC5:** no relay pair regresses: CORPLAP-1 → neo16 L4 p95 and freeze count stay within the baseline's
  spread, with every cut on.
- [x] **AC6:** C6 either closes the "Chrome ~80 ms jitter-buffer floor" Known Issue with an L4 number on
  the `<video>` path, or rewrites it with the measured floor. **Closed, field-checked on agent 0.4.139**
  (§9). On the `<video>` path with no switch set, C6 is negotiated by default. Chrome's buffer reads 0.1 ms,
  and L4 batch p50s read 34–44 ms (median 37), p95 46–61 ms, with 0 of 480 probes lost. On 0.4.138 the same
  path read p50 78–362 ms with C6 off. Without the extension, #2284's fix keeps Chrome's buffer at 7.6 ms
  on average, where it was 193 ms. The Known Issue is gone from `CLAUDE.md`.
- [ ] **AC7:** **Docs:** `docs/remote-control.md` §12 replaces its target table with the measured budget (a
  mermaid diagram of the stages and their L4 shares) and each cut's switch. Linked from `docs/README.md`.

## 7. Open decisions

1. **The target.** Recommended: p50 ≤ 50 ms and p95 ≤ 80 ms, direct, 60 fps, fixed after the P0 baseline and
   written into AC4 then.
2. **The GPU clock pin default.** It costs idle power while a session is live. Recommended: on for NVENC
   sessions on perMachine installs, if P2 shows it moves L4. Per-user installs cannot pin (no admin rights,
   `gpu_clock.rs` L21–24), so they keep it off.
3. **Input gap 0.** One message per `pointerrawupdate` can mean 1 kHz input on a gaming mouse. Recommended:
   measure 0, 2 and 4 ms; ship the smallest gap that does not flood the input DC.

## 8. Out of scope

- Raising the frame rate: the high-refresh FR (wave 2).
- Congestion control and the transport: [FR-63](FR-63-one-delay-based-rate-controller.md),
  [FR-17](FR-17-partial-reliability-video.md), [FR-74](FR-74-text-clarity-on-direct-paths.md) P5.
- The GPU frame path (zero-copy): its own FR (wave 2). It is about CPU cost and 4K, and moves direct-path
  latency little.
- Building the instrument: [FR-16](FR-16-rc-quality-benchmark.md) L0/L4.

## 9. Field-verification log

Planned cells. Each records the deployed build first.

| # | Cell | Pair | Path |
|---|---|---|---|
| 1 | direct LAN, NVENC | neo16 → MacBook | direct |
| 2 | direct LAN, VideoToolbox | MacBook → neo16 | direct |
| 3 | direct, QSV | neo16 → CORPLAP-3 | direct where the VPN allows, else noted |
| 4 | relay, the no-regression cell | CORPLAP-1 → neo16 | structural relay |

| # | Date | Build | Result |
|---|---|---|---|
| L0 | 2026-10-13 | P1 branch, unoptimised, Windows dev box | **Wrong turn, recorded.** The first run read `gate_lgcy` p50 59.8 ms and `gate_slot` p50 45.5 ms, far above `clean`'s 12.6. The emulation stood a timer in for `FrameArrived`, and when the slot was empty it counted that timer's overshoot (up to a Windows timer tick) against both gates. Real WGC wakes the reader on the event itself. Fixed: a frame waited for lands when the wait ends; a frame already in the slot lands on schedule, and its wait is the gate's |
| L0 | 2026-10-13 | the same | **Green:** `clean` p50 12.8 ms · `gate_slot` p50 13.9 ms, p95 18.3, 25.1 fps from the 25 fps source · `gate_lgcy` p50 36.1 ms, p95 51.3, **21.9 fps**. So the slot-first gate cut p50 by **22.2 ms** (bound: ≥ 10, a quarter of 40 ms), and it also kept the frames the legacy gate dropped when its cadence fell a whole period behind |
| L0 | 2026-10-13 | the same | **Negative control, red:** a slot-first gate that always sleeps a period (one marked line in `SlotFirst::wait`) failed `gate_slot: 12.7 fps decoded from a 25 fps source` (exit 101). Its p50 difference was 4.9 ms (legacy 35.7, broken slot-first 30.8), which the C1 bound would have refused too. Restored from the commit; the diff was that one line |
| L0 | 2026-10-13 | P5 branch, unoptimised, Windows dev box | **C6, the wire, green.** The controller offers `playout-delay` the way Chrome does. With the switch off (every cell but one), the answer negotiates nothing, so the default stays byte-identical. `playout0` (switch on): negotiated, **217 of 217** video packets at 0/0 (0 other, 0 without), 30.2 fps, p50 11.9 ms, the same as `clean`. L0's controller has no jitter buffer, so this proves the wire, not the effect on Chrome |
| L0 | 2026-10-13 | the same | **Negative control, red:** with the switch on but the pump not writing the extension (one marked line), the test failed `playout0: want playout-delay 0/0 on every packet, saw PlayoutSeen { negotiated: true, zero: 0, other: 0, without: 217 }` (exit 101). Restored from the commit; the diff was that one line |
| P5 | 2026-10-16 | **Release build, field.** Agent **0.4.138** (MSI, service) on a throwaway vmtest Win11 guest (KVM on a fleet host, 1280×800, Microsoft Basic Render Driver only); the **production viewer** in headless Chromium on a LAN neighbour, forced onto the RTP track (`roomler-rc-video-transport.v2 = webrtc`), L4 target mode against `roomlerd probe-target`. C6 switched through the service's own `Environment` value and a restart | **Wrong turn, recorded.** C6 off, then on (the remote description carried the extension only in the second cell). Chrome's jitter buffer averaged 12.8 ms, then 0.7 ms, but L4 read batch p50s of 827–904 ms (median 859), then 825–872 ms (median 836). On top of that, 28 % and 25 % of probes went unanswered within the 2 s TTL. FR-16's DataChannel row on the same kind of guest had read 42–49 ms. The agent log said why: `encoder selected: mf-h264 (hardware)` over `pipeline ready backend="sw"`. That is Microsoft's software MFT, the cascade's last fallback when no hardware MFT opens. The encoder, not the browser: [#2283](https://github.com/gjovanov/roomler-ai/issues/2283) |
| P5 | 2026-10-16 | the same guest, with `MESHHARBORD_ENCODER=software` (OpenH264) | **C6's A/B, green**, with C6 on first this time to reverse the order. **On:** Chrome's jitter buffer 0.1 ms (twelve 10 s windows, 0.0–0.2); L4 batch p50s 35.0–39.5 ms (median 36.9), p95 51–64 ms, 0 of 480 probes lost. **Off:** jitter buffer 192.7 ms on average, its windows climbing 46 → 326 ms and then easing to 113–189 ms; L4 batch p50s 78–362 ms (median 203), p95 206–556 ms, 2 of 482 lost. Chrome's own target (`jitterBufferTargetDelay` per emitted frame) sat at ~50–62 ms in both cells, so most of the off cell's hold sits above the target. [#2284](https://github.com/gjovanov/roomler-ai/issues/2284) is the suspected cause. Both cells: H.264, 4–7 fps of damage from the probes |
| P5 | 2026-10-16 | the same guest and settings; the viewer's own transport pick | **Control, the DataChannel path:** `data-channel-vp9-444` (libvpx 4:4:4, the WebCodecs worker). L4 batch p50s 43.8–51.9 ms (median 45.5), p95 59–75 ms, 0 of 480 lost, in line with FR-16's 10-13 row. With C6 on, the RTP track ran about 8 ms faster than the DataChannel on this guest. Not an AC cell: a VM, software encoders, headless Chromium. The jitter buffer is the browser's own logic, which headless runs unchanged, and the viewer's display is outside L4 either way |
| L0 | 2026-10-16 | C6 default-on branch, unoptimised, Windows dev box | **C6 on by default, green.** `playout0`, now run with the switch unset: negotiated, **246 of 246** video packets at 0/0, 30.2 fps, p50 7.5 ms. Every other cell forces it off and negotiates nothing (`clean` p50 7.7 ms) |
| L0 | 2026-10-16 | the same | **Negative control, red:** the parser's default turned back off (one marked line) failed `playout0: want playout-delay 0/0 on every packet, saw PlayoutSeen { negotiated: false, zero: 0, other: 0, without: 0 }` (exit 101). Restored from the commit; the diff was that one line |
| L0 | 2026-10-16 | #2284's branch, unoptimised, Windows dev box | **#2284, the timestamps, green.** The new `cadence` cell (frames at gaps of 33, 33 and 200 ms, repeated): 72 frames, each frame's RTP step within p50 **0.9 ms**, p95 5.6 ms of its arrival step. Every other cell prints the same error, 0.1–3.3 ms at p50 |
| L0 | 2026-10-16 | the same | **Negative control, red:** the pump's old write put back (one marked line: advance after the frame, by the gap before it) failed `cadence: … p50 158.8 ms, p95 176.5 ms (want … ≤ 10 ms and ≤ 40 ms)` (exit 101). At a fixed rate the old write hides: `clean` read p50 4.1 ms. Restored from the commit; the diff was that one line |
| R | 2026-10-16 | **Release build, field.** Agent **0.4.139** (MSI, service) on a kept vmtest Win11 guest (KVM, 1280×800, Microsoft Basic Render Driver only), **no `MESHHARBORD_*` switch set**. P5's harness: the production viewer in headless Chromium on a LAN neighbour, forced onto the RTP track, with L4 in target mode against `roomlerd probe-target` | **The defaults, green: C6 and #2283 together.** The agent's log: the MF pipeline ended on `backend="sw-pure"`, then "ended on Microsoft's software MFT with no GPU behind it - using openh264 instead (#2283)", then `encoder selected: openh264 (software)`. Every session logged `rtp playout-delay 0/0 offered on the video track (FR-98 C6)`, and the remote description carried the extension. Chrome's jitter buffer: **0.1 ms** (twelve 10 s windows, 0.1–0.2). L4 batch p50s **34.2–43.8 ms** (median 37.2), p95 46.0–60.7 ms, **0 of 480** lost. P5's Auto pair on 0.4.138, on the same kind of guest, read batch-p50 medians of 836–859 ms, with 25–28 % of probes unanswered |
| R | 2026-10-16 | the same guest, `MESHHARBORD_RTP_PLAYOUT_DELAY_ZERO=0` (and a restart) | **#2284, green: the track's timestamps.** The extension is not negotiated, so Chrome's jitter buffer runs on its own estimate. **7.6 ms** on average (median window 2.4 ms, 0.1–32.7). L4 batch p50s 46.0–73.5 ms (median 51.7), p95 66–222 ms, 1 of 480 lost. The red is P5's off cell on 0.4.138 with the same encoder: 193 ms on average, growing from 46 to 326, and L4 p50s 78–362 ms (median 203). So the off-by-one, not the browser, was most of Chrome's hold, and a browser that never offers `playout-delay` now gets a few ms of it |

## 10. Related

- [FR-16](FR-16-rc-quality-benchmark.md): L0 and L4, the instrument.
- [FR-1](FR-1-remote-desktop-drag-smoothness.md) P6: the 8 ms input gap and `pointerrawupdate`.
- [FR-70](FR-70-media-pipeline-leaves-the-runtime.md) M3: why the switches are read once per open.
- [FR-17](FR-17-partial-reliability-video.md): where intra-refresh belongs.
- [#2283](https://github.com/gjovanov/roomler-ai/issues/2283) and [#2284](https://github.com/gjovanov/roomler-ai/issues/2284):
  the two RTP-track faults P5's cells found (§4.2).
- The program: [`docs/plans/stardesk-teardown-program.md`](../plans/stardesk-teardown-program.md).
