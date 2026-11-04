# From patch-work to architecture: remote-desktop rate control

## Context

FR-59 (0.4.47 → 0.4.50) is the fourth program in a row — after FR-1, FR-15, FR-35 — that added a
controller *around* the DataChannel pump's rate/quality loop instead of replacing it. Its
2026-09-02 regression showed the cost, and the operator asked for an honest ratio of patch-work to
architecture and a plan that shifts it. Decisions taken during planning: **FR-A first**; **C1 =
never let ICE select an overlay-adapter address for RC**; **merge PR #1240 now, tag it with FR-A's
first release**.

### The ratio, in numbers (codebase map, 2026-09-02, `C:\dev\_wt\slowlink` @ `fd15b9fc`)

| what | size |
|---|---|
| controllers / estimators / heuristics that move rate, fps, dims or force a keyframe | **34** in `agents/meshharbord/src/encode/*` + the two pumps |
| of which compensate for "a rate change costs an IDR" | 9: coarsen ladder, deferred applies + `DEFER_QUIET`, 15-s thrift, background swap, settle-KF thrift, refine-vs-cap fight, opener grace, FlipTracker cooldown, kf_gate rebuild cooldown |
| of which are a second estimate of the same pipe | 8: occupancy AIMD, blocked-send goodput, FR-35 learner, rate memory, P1 floor relief, P3 arrival clamp, P4 drain, FR-15 age loop (+ P6/P8 glue) |
| kill switches | 11 pub `*_enabled()` in `encode/mod.rs` + 2 private + ~11 env-only knobs; a config key touches six places (`config_surface.rs` KEYS/get/set, `config.rs` field + `env_bridge_bools`, `enrollment.rs` default) |
| code / churn | core ≈ 10,490 lines / 198 tests; pumps ≈ 3,440 lines inside the 10,368-line `peer.rs`; 52 commits in five weeks; 9 FR specs touch it |

Worth keeping (architecture): pure controllers with explicit `Instant` (they unit-test); the
viewer→agent arrival/queue feedback (the one signal that cannot be fooled); the kill-switch +
config-surface discipline; the per-session heartbeat persisted to `agent_logs` (Mongo, 7-day TTL,
indexed by `session_id`) — the only structured per-session record and the shadow channel.

### The three roots

1. **A rate change costs an IDR** (`encode/ffmpeg/encoder.rs::set_bitrate` :1585–1671). Verified
   against FFmpeg **n8.1.2** (what all three vendor workflows build): NVENC's `reconfig_encoder`
   sets **`resetEncoder=1; forceIDR=1`** inside `if (reconfig_bitrate)` — an IDR on every move;
   QSV/AMF/VideoToolbox take a **full rebuild** (`force_keyframe=true`) under a stale comment
   (:1624) — `qsvenc.c` runs `update_parameters()` on **every** frame and `update_bitrate()`
   re-reads `bit_rate`/`rc_max_rate`/`rc_buffer_size` → `MFXVideoENCODE_Reset` (no reset option
   attached; whether the driver starts a new sequence is a measurement). **Our QSV sessions run
   CBR, not QVBR**: `select_rc_mode` tests `rc_max_rate == bit_rate` before the `global_quality`
   branch and we set both to the cap (:358, :1043–1045) — which is why every 0.4.49 frame was
   exactly `target ÷ fps ÷ 8` bytes. VideoToolbox sets AverageBitRate at init only (patchable the
   way WebRTC's VT encoder does it). Nine heuristics ration this cost; on LAN pairs the AIMD crosses
   a rung nearly every window (44 swap IDRs/day on one host).
2. **No single model of the pipe** — eight estimators composed with "the lower of" rules in
   `RateGovernor::pre_encode_tick` (`encode/governor.rs:482`) and `tick_viewer_window` (:708).
3. **The wrong data path.** ICE nominated the overlay host pair (`100.65.0.5 ↔ 100.65.0.6`) so
   video rode WebRTC → TUN → WireGuard → DERP/TLS → corp VPN, shed by our own DERP mux
   (`queue_max_age` 100 ms, `crates/tunnel-core/src/transport/derp.rs:64–77`). The rc.319
   interface filter (`peer.rs:338`, `is_overlay_iface` :9289) is a **no-op on Windows** — webrtc-util
   reports every adapter with name `""` (`webrtc-util-0.10.0/src/ifaces/ffi/windows/mod.rs:331–348`)
   — and misses macOS `utunN`; srflx (`agent_gather.rs:729–758`) and remote candidates
   (`peer.rs:1273–1320`) are never filtered; host↔host type-preference wins whenever it connects.
   #1237 is the same class: "any interface other than ours" (`tun.rs:2427–2472`).

## Goal

One apply path that does not cost an IDR (FR-A), one controller (FR-B), one rule for RC addresses
(FR-C) — each shadow-first with field evidence, each deleting more than it adds; the FR-59 field
instrument (bytes-per-frame ÷ expected, age p50/p90/max, IDR count, `chunk too short`) promoted
from scratchpad to `scripts/`.

---

## FR-A — Encoder rate changes without an IDR (first)

**A0 — measure on silicon.** Extend `Command::EncoderSmoke` (`main.rs:241–251`, dispatch
`encoder_smoke_cmd` :4059) with `--reconfigure-sweep [--width/--height 1280×800]
[--frames-per-rung 30] [--constrained] [--json]`: synthetic desktop frame with a moving 200×200
block (solid colours make P-frames ~0 bytes and hide CBR/QVBR); 30 frames at 6 M, then rungs
`4.5M 3M 2M 1.5M 1M 750k 550k 400k 300k 200k` down and back (20 changes via `set_bitrate`). Per
rung: `applied_maxrate, set_bitrate_ms, key_packets` (`AV_PKT_FLAG_KEY`, encoder.rs:1491; size
heuristic as the second detector for vp9_qsv), `burst = first3_max/trailing_mean`, `ratio =
mean_bytes/(rung/fps/8)`. **Pass** = 0 key packets after the opener, `set_bitrate_ms < 5`, ratio
±25 % by frame 10, burst ≤ 2×. Hosts: CORPLAP-1 (`hevc_qsv`, `low_power` 1 and 0), an
Arc/Meteor-Lake host (`av1_qsv`), the RTX box (`hevc/av1_nvenc`), one Apple Silicon Mac
(`hevc_videotoolbox`); AMD recorded as unmeasured. Add a defaulted trait method
`VideoEncoder::rate_stats()` (`encode/mod.rs:932`) so the sweep reads counters. The sweep bypasses
the coarsen gate (:1591–1594).

**A1 — in-place applies, gated.** Replace `supports_dynamic_bitrate = name.contains("nvenc")`
(encoder.rs:1062) with `rate_mode: RateReconfig::{InPlace, Rebuild}` resolved at open (InPlace for
`*_nvenc`, `*_qsv`; Rebuild for `*_amf`, `*_videotoolbox`); keep `supports_dynamic_bitrate()` (:1471)
= `InPlace` so no pump call site changes. QSV in-place arm writes **`bit_rate = target;
rc_max_rate = target; rc_buffer_size = target × hrd_pct/100`** (CBR: TargetKbps must move with
MaxKbps). Fix the existing NVENC bug: :1615 writes `rc_buffer_size = target` while the open sized it
`maxrate × hrd_pct/100` (:262) — store `hrd_pct` on the struct. Dead-band: InPlace applies raw
targets when `|Δ| ≥ 3 %` (a QSV Reset flushes the pipeline). Kill switch `encoder_inplace_rate`
(env `ROOMLERD_ENCODER_INPLACE_RATE`), **default OFF in the PR, ON after A0 passes on CORPLAP-1**
(six places: `config_surface.rs` KEYS near :630 / get :877 / set :1290; `config.rs` field :879,
default :1996, `env_bridge_bools` :2122 array 72→73; `enrollment.rs:203`; parity test :1935).
Counters `rate_moves, rebuilds, idr_count` on `FfmpegEncoder` → heartbeat (`peer.rs:6818–6771`) with
`rate_mode`; read `idr_count` against `keyframe_requests` (`session_telemetry.rs:29`). A startup
`probe_and_cache_rate_reconfig` (like `VP9_QSV_IDR_VERDICT`, encoder.rs:71): open 640×480, change
rate once, count key flags — per host, per codec, OnceLock; a driver table is not evidence.

**A2 — NVENC (and VT) without the forced IDR.** Patches in `.github/ffmpeg-patches/`:
`0001-nvenc-no-idr-on-bitrate-reconfig.patch` (delete `params.resetEncoder = 1; params.forceIDR =
1;` inside `if (reconfig_bitrate)`; per `nvEncodeAPI.h` a rate-only reconfigure needs neither;
optionally behind a private `reconfig_idr` option so it is upstreamable),
`0002-videotoolbox-runtime-bitrate.patch` (`VTSessionSetProperty(AverageBitRate/DataRateLimits)` in
`vtenc_send_frame` on change, as WebRTC's VT encoder does), `0003-amf-runtime-bitrate.patch`
(written, disabled, unmeasured). Applied in all three builders: Linux `patch -p1` after the tarball
(`vendor-ffmpeg-windows.yml:198–200`), macOS after the clone (`vendor-ffmpeg-macos.yml:62–64`),
Windows by injecting `PATCHES` into the copied portfile's `vcpkg_from_github(` (same anchor-replace
technique :75–95). Drift gate: each builder writes `ROOMLER-PATCHES.txt` (sha256 per patch) into
the asset and `release-agent.yml`'s three fetch steps (:341–352, :1002–1004, :1926–1934) assert it
matches `.github/ffmpeg-patches/*`. `const NVENC_RECONFIG_FORCES_IDR: bool` flips to false in the
asset-bump PR; the pump's `held_increase` arm (`peer.rs:6294–6274`) keys on it.

**A3 — VideoToolbox / AMF.** From A0 on a Mac: patch 0002 + `InPlace`, or keep `Rebuild` on a
simple "rebuild at settle, ≥ 15 s apart" rule; AMF stays `Rebuild` on the same rule.

**A4 — delete, one shippable PR each:**

| PR | delete | anchors | precondition |
|---|---|---|---|
| A2 | motion-defer: `deferred_bps`, `DEFER_QUIET`, `last_motion_at`, `last_deferred_apply_at`, `held_increase`; `rebuild_apply_allowed` + `relay_deferred_apply_allowed` (+tests); `relay_idr_thrift` narrows to settle-KF suppression | `peer.rs:4913, 4856–4863, 6100–6147, 6158–6194, 6251–6256`; `mod.rs:417–474` | A0 pass on QSV, switch ON one release |
| A3 | background swap (`bg_rebuild`, `pending_swap`, `swap_wanted`, `SWAP_MIN_INTERVAL`, `last_swap_at`; `rebuild_spec`/`open_rebuilt`/`adopt_rebuilt`); **`coarsen_bitrate` + `BITRATE_LADDER_BPS`**; `bg_rebuild` key | `peer.rs:4980–4991, 5022–5088`; `encoder.rs:1525–1546`; `aimd.rs:285–338`; `mod.rs:370–381` | VT measured or kept on the settle rule |
| A4 | unify `on_encoder_rebuilt_mirror_only` into `on_encoder_rebuilt` (VP9 divergence) | `governor.rs:695–699`; `peer.rs:3832` | — |

Stays: dims/chroma/backend rebuilds (:5749–5813), FlipTracker rebuild (:5112–5136), error ladder,
`kf_gate` (kf_policy.rs), `send_epoch` for those rebuilds.

**Acceptance:** encoder tracks the target within one frame of an apply (bytes-per-frame ratio ≈ 1.0
within 2 s of a change) and a 5-minute constrained session's `idr_count` ≤ dims changes + viewer
keyframe requests. **Risks:** QSV Reset starting a new sequence on some driver (probe per host/codec,
`Rebuild` fallback, patch `0004` attaching `mfxExtEncoderResetOption{StartNewSequence=OFF}` if
systemic); BRC reset burst (A0's burst column; `max_frame_size` is runtime-updatable in qsvenc as a
per-frame cap — incidentally the FR-31 lever); AMF unmeasurable; VT rebuild cost unknown; ladder
hysteresis gone (AIMD's own rate limits ≤ 2 moves/s + the 3 % dead-band until FR-B formalises
`apply_deadband`); `adopt_rebuilt`'s staleness refusal must include `rate_mode`. **A5 (separate
A/B, later):** switch QSV to QVBR (`bit_rate = 0.9×maxrate`, keeps `global_quality`) — stops CBR
padding idle frames.

---

## FR-B — One delay-based rate controller, shadow-first

**The controller** — pure `encode::ratectl::Controller` (explicit `now`, ~600 lines with tests).
Inputs: per frame `SendSample { capacity, depth, bytes_inflight, queue_budget, now }` at
`pre_encode_tick`'s position; per 1 s `Window { fps, struggling, age (avg,min,rtt), rx_bps,
queue_ms, goodput, sent_bps, frames_lost, delay_slope_ms_s }` at `tick_viewer_window`; events
(full channel, overflow, blocked-send stall). **Viewer adds** (all optional; older viewers omit;
`decodeStatWireMessage` `useRemoteControl.ts:1237–1270`, parser `peer.rs:7492–7365`): `frames_lost`
(chunk gaps, already in `rc-hevc-worker.ts:325`), `frames_rx`, `delay_slope_ms_s` (least-squares
slope of the window's per-frame `arrival − wire` — `QueueDrift` in `rc-hop-stats.ts:102–138` already
holds the pairs), `age_p95_ms`. **Bounds:** `RateDomain { floor, ceiling }` — the single source of
pins; floor is a constant per path (`area_min_bitrate_bps` direct, 200 k constrained), ceiling =
`rate_plan` × shared split × encode factor, bounded by `relay_max_hi_bps` on Relay. **Priors:**
`remembered_bps` (rate memory re-keyed on `(remote_ip, PathClass)`) and `PathClass { LanDirect,
WanDirect, Overlay, Relay }` from the nominated pair. **State machine** (GCC-shaped, level-held):
Normal → OverUse on two consecutive windows of any of `delay_slope > +50 ms/s`, `age − floor ≥
70 ms`, loss ≥ 2 %, goodput < 0.9×target, or immediately on a sustained full channel / a hard
stall; OverUse → Hold applies `0.85 × measured` (rx_bps on Relay/Overlay, `min(goodput, rx)` on
direct; never below 0.5×target per window) and **holds while the age level is elevated** (the
derivative lesson FR-59 paid for twice); a deep level on a constrained path → one bounded pause
≤ 300 ms, **direct paths never pause**; Hold → UnderUse after 2 clean windows: slow-start ×1.08 per
window below 50 % of ceiling, additive `max(target/16, 25 k)` above; the remembered rate opens at
`min(0.85×remembered, ceiling)` as a soft cap for 10 s; `fps == 0` windows (a DERP stall) are **no
evidence**. Outputs `Decision { target_bps, rung: QualityRung { fps_cap, long_edge }, reason }`
through `apply_deadband` (decreases immediate ≤ 1/500 ms, increases ≤ 1/2 s, `|Δ| ≥ 5 %`); the pump
executes a rung only at a settle.

| existing | fate |
|---|---|
| AIMD; coarsen ladder | replaced; deleted (A3) |
| goodput estimator | kept as a sensor (ceiling clamp folded) |
| FR-35 learner; rate memory | replaced by the increase law bounded by `relay_max_hi_bps`; kept as prior (`opener_growth_target` folded into the 10-s slow start) |
| P1 relief / P6 contradiction / P8 opener | replaced / replaced (a prior cannot pin) / kept |
| P3 LinkLoop / P4 drain / FR-15 AgeLoop | folded (drain: constrained-only, ≤ 300 ms, never on direct; the age floor ring stays as `path_floor_ms`) |
| viewer-rate divisor | kept, fed by `struggling` only |
| encode pressure / FpsPace / downscale tier / refine / settle KF / kf_gate / plan_dims / rate_plan | kept (tier → `QualityRung` later) |
| byte gates; shared split | kept, denominated in `ctl.reference_bps()`; applied to `ceiling` before `RateDomain` |

**B0 — the simulator + trace replay** (`encode/sim.rs`, `#[cfg(test)]`): `PipeSim { rate_bps,
buffer_bytes, loss_pct, rtt_ms, stalls }` (token-bucket FIFO, arrival = `max(prev, at+rtt/2) +
bytes×8/rate`, frozen in stalls, tail-drop, seeded loss, reports blocked time in the `GoodputSink`
shape); `EncoderSim { fps, target, motion(t) }` (CBR bytes, IDR = 25×, set_bitrate with/without an
IDR); `ViewerSim` folding arrivals into decodestat-shaped windows (age, rx_bps, `queue_ms =
Σ(Δarrival−Δwire)` — the same formula as `rc-hop-stats.ts:112–127`, loss, slope). Harness
`run(scenario, ctl) → Trace` with assertions `settling_time`, `steady_state_error ≤ 15 %`, `p95 age ≤
floor + 150 ms`, `idr_count`, `pauses_on_direct == 0`. **Trace-replay fixtures** (CSV, one row per
2-s heartbeat: `t_s,target_bps,frames_encoded_d,bytes_d,bytes_inflight,goodput_bps,viewer_age_ms,
viewer_age_floor_ms,rx_bps,queue_ms,link_congested,drains,constrained,w,h,fps`) extracted by
`scripts/rc-trace-extract.py` from `agent_logs` (`list_for_agent(?session_id=…)`,
`routes/agent_log.rs:208`) into `agents/meshharbord/tests/fixtures/ratectl/`; ground truth per window =
`rx_bps` when `queue_ms > 0`, else goodput, else hold; assertions = over-drive integral
`Σ max(0, target − 1.1×pipe)` ≤ budget and recovery ≤ N windows per stall. Four fixtures: **airport
hotspot** (goodput 65–395 k, target climbing → ≤ 1.1×pipe within 5 s, never climbs while age is
elevated); **CORPLAP-1 DERP** (20–400 k with 1–4 s stalls → no increase in a stall, recovery ≤ 3
windows, ≤ 1 pause per stall); **LAN Wi-Fi burst** (30 KB inflight spikes at 5 M → zero pauses, ≤
one 15 % cut per burst, no clamp > 10 s); **fast pair misremembered slow** (seed 200 k on 20 M →
≥ 50 % of ceiling in 10 s, ≥ 90 % in 30 s).

**B1 — shadow.** `RateGovernor` gains `shadow: Option<ratectl::Controller>` (on by default,
observe-only), fed at the live positions (`pre_encode_tick` entry :482 → `observe_send`; after the
floor/ceiling resolve :622 → `set_domain`; `on_backpressure_skip` :465, `on_send_overflow` :645,
`note_send_stall` :667 → events; `tick_viewer_window` after the unpacks :738/:748/:785 →
`fold_window`); `pre_encode_tick` grows `bytes_inflight, queue_budget` at both pumps
(`peer.rs:6271`, `:3989`). Heartbeat adds `shadow_target_bps, shadow_state, shadow_measured_bps,
shadow_disagree_pct, shadow_pauses, shadow_reason`. `scripts/rc-shadow-report.py` reads a week of
`agent_logs` by session and reports per `PathClass`: disagreement p50/p90 and its sign in
elevated-age vs clean windows. **Flip criterion:** ≥ 20 constrained + 20 direct sessions, shadow
≤ live in ≥ 90 % of elevated-age windows, all four fixtures green.

**B2 — flip:** one tribool `ratectl = shadow|live|off` (six places); `live` routes the decision into
the same apply arms; the AIMD stays constructed but unread for one release (heartbeat then logs
`aimd_target_bps` as the shadow). **B3 — retire:** batch A2 `relay_idr_thrift` narrowed; A3
`bg_rebuild`; B3a (one release after `live`) `measured_ceiling, slow_link_floor, seed_contradiction,
viewer_rate_clamp, queue_drain, relay_age_feedback`; B3b `constrained_queue_measured` (budget =
`reference_bps`), `slow_link_profile` (→ rung), `relay_ceiling_learn` + `relay_max_hi_kbps` (→
prior bound), `area_min_bitrate` (→ `RateDomain` rule), and delete `aimd.rs`, `ceiling_learn.rs`,
`LinkLoop`/`AgeLoop`, the P1/P3/P4/P6 governor arms. Retired keys join a `RETIRED_KEYS`
accept-and-ignore list for one release (mirrors `mod.rs:136–145`). Tests: aimd (15) → ratectl
invariants; governor (32) → ~15 retire, the rest re-anchor; viewer_rate (24) → 10 become sensor
tests; ceiling_learn (12) → 4 prior tests; goodput/rate_profile/encode_pressure/kf_policy stay.

**Risks:** lumpy TURN-TCP (rx_bps primary on Relay, goodput only a stall detector, 2-window
confirmation, 0.5× per-window floor; fixture 2); DERP stalls (no evidence, bounded relay-only
pauses); multi-viewer (fold the worst follower's `rx_bps/queue_ms`, `media_share.rs:423`); VP9
parity (libvpx takes raw kbps with no IDR — same controller; unify the `mirror_only` divergence
before B2).

---

## FR-C — The right data path (decision: never for RC)

**C1 — ICE never selects an overlay address for remote desktop.** Three mechanisms, one kill switch
`overlay_ice_candidates` (env `ROOMLERD_ICE_OVERLAY_CANDIDATES`; ON restores today):

1. **Own-adapter `ip_filter` at gather** — `SettingEngine::set_ip_filter` next to `peer.rs:338`
   (`vendored/webrtc/src/api/setting_engine/mod.rs:195–197`, evaluated per address in
   `webrtc-ice/src/util/mod.rs:129–132`) with the addresses **on our own adapters**, not a CIDR:
   `if_addrs::get_if_addrs()` filtered by `is_overlay_iface(name)` on Windows/Linux, plus LocalAPI
   `status().overlay_ip/ip6` (`localapi/src/lib.rs:97–101`) for macOS `utunN`. An ISP CGNAT
   address lives on the physical NIC and is never dropped — this retires the objection at
   `peer.rs:334–337`.
2. **srflx**: the mapped address bypasses every filter (`agent_gather.rs:729–758`) — a 3-line
   addition to the already-forked webrtc-ice (`webrtc-ice.patch`, `--regen`) applying `ip_filter`
   to `xoraddr.ip` at :744, plus a belt at the signaling hop `peer.rs:717–733`.
3. **Remote candidates** in `add_remote_candidate` (`peer.rs:1273–1320`), after mDNS resolution:
   drop non-relay candidates whose address equals a LocalAPI `peers()` overlay IP or our own (same
   query as :1644–1651, 400 ms timeout, fail-open); relay-typed exempt (keeps the loopback TURN,
   `rc_local_turn.rs`, `relay_addr_is_fast_local` `encode/mod.rs:691–690`).

Plus **PathClass-lite**: the class in the `per-session ICE path detected` line (`peer.rs:1514–1513`)
and in the FR-35 memory key (`peer.rs:4595` → `"{ip}|{class}"`, which fixes "a fast day carried
onto a slow one"); an additive `carrier` field on the LocalAPI peer entry (`localapi/src/lib.rs:32–38`
has only `Relay`) so DERP / TURN / org relay are distinguishable. Mitigation for the one path lost
(proxy-only egress, 443 only): a `turns:` listener on 443 on coturn, or the loopback-TURN opt-in.
Update `docs/multi-org.md:340–341` (its "ICE never gathers on roomler-*" is true only on Linux) and
`docs/overlay-nat-traversal.md` with the rule.

**Field verification** (CORPLAP-1 multi-org with the VPN on; CORPLAP-3 LAN): `ICE: gathered local
candidate` shows no `100.6x.`/`fd72:` host or srflx; `per-session ICE path detected` shows a
relay/srflx pair outside the overlay ranges on CORPLAP-1 and the `192.168.0.x` pair on CORPLAP-3
(p50 ≤ 50 ms); no `overlay carrier under the nominated pair is not direct` line; flipping the switch
brings the old `100.65.0.5 ↔ 100.65.0.6` pair back.

**C2 — #1237, the sibling route war (independent; do first).** Two facts from the design pass:
each per-org adapter already holds a **narrowed** on-link `/(96+plen)` v6 address
(`overlay.rs:673–675` → `tun.rs:3331–3346`), but `defend_self_route` (`tun.rs:2439–2456`) evicts and
asserts the **whole /96** on every adapter — the damage is the route-change notification storm, not
a routing hole; and the same missing notion of "own adapters" makes `non_overlay_v4_addrs`
(`tun.rs:2287–2302`) count the sibling's address as a foreign CGNAT address, so the primary's
**block floor is silently withheld** on multi-org hosts.
- Own-adapter registry in tunnel-core (`tun.rs` `mod system`: `OWN_TUNS: Mutex<BTreeMap<luid,
  if_name>>`, registered at the end of `SystemTun::up_with`, deregistered in a new `Drop`;
  `is_own_luid`/`own_if_names`; alias belt `IF_NAME`, `IF_NAME-*` for a second process).
- Exempt own LUIDs in `evict_competing_v4/v6` (:677, :863), `evict_foreign_in_block_v4` (:751),
  `foreign_in_block_fp` (:813); exclude own if_names in `non_overlay_v4_addrs`; `evict_warn` gains
  `competitor_alias`.
- Nobody asserts the whole /96: defend `derive_overlay_v6(connected_v4.net)` masked to
  `v6_onlink_plen` (byte-identical for legacy single-org; longest-prefix still beats AnyConnect's
  mirrored /96); WARN at org bring-up when two orgs' blocks overlap. Linux/macOS have no
  self-defense wave (latent only on overlapping blocks).
- Kill switches `overlay_sibling_exempt`, `overlay_v6_defend_narrow` (default ON; OFF = today).
- Tests: pure `is_foreign_row`, `defended_ula_prefix` golden vectors, `floor_safe` with a sibling
  excluded; a two-runtime mock-TunIo test that neither evicts the other's prefix.
- Acceptance (neo16, CORPLAP-1/-3, 24 h): sibling evictions **0** (today 718/day), revalidation
  pokes at idle baseline (today ~100/min), no withheld block floor on the primary.

---

## Process — how the ratio actually shifts

1. **Shadow-first is the rule for `encode/`**: no controller change ships live without one release
   of shadow logs — written into `docs/fr/README.md`.
2. **Simulation before the fleet**: B0's simulator + trace replay gates every rate change; the
   netem harness leaves the acceptance path (it cannot host a QSV encoder, a pair memory, or
   viewer→agent loss — every FR-59 mechanism needed one).
3. **The field A/B is a script** — `scripts/rc-ab.sh <agent> <minutes>`: Playwright opens the
   viewer (an `ui/e2e` RC fixture: `remote-session-smoke.spec.ts` has the Connect flow,
   `vmtest-remote.spec.ts:99` the wiggle; a Worker-timed motion driver replaces it), pulls the
   agent's series (the FR-59 helper moved from the scratchpad into `scripts/rc-field.sh`), prints
   the before/after table. CORPLAP-1 from neo16 is the standing cell; add it to the vmtest matrix.
4. **Kill switches get a retirement date** — a table in `docs/fr/README.md` (switch, default,
   evidence to flip, retire-by release, deletion PR); today's 11 + env-only knobs are the first
   rows, A4/B3 their exits.
5. **Invariants in types** — `RateDomain`, `PathClass`, `Option<Instant>` for "never happened"
   (`clock::instant_before` is the bridge, not the destination).
6. **Upstream** the sctp fix (webrtc-rs PR) and the nvenc patch (FFmpeg `reconfig_idr` option);
   drop the forks when released.
7. **A release window where the fleet is not the harness** — shadow mode buys it; the 4-hour
   updater poll and "Update now" stay.

## Sequencing (≈ 17 engineering days over ~4–5 weeks)

| order | item | size | depends on |
|---|---|---|---|
| 0 | merge #1240 (tag with A's first release); FR-A/-B/-C issues + specs with ledger rows | hours | plan approval |
| 1 | A0 sweep on CORPLAP-1 / Arc host / RTX / Mac ∥ C2 (#1237) | 1 d + field, 2 d | — |
| 2 | A1 inert → switch ON → 1-day CORPLAP-1 soak → A2 (+ nvenc/VT patches, asset re-vendor ×3) → A3 | ~5 d | A0 |
| 3 | B0 simulator + fixtures ∥ C1 + PathClass-lite (+ field on CORPLAP-1/-3) | 3 d ∥ 3 d | — |
| 4 | B-1 controller with sim tests → B1 shadow → one release of fleet logs | 5 d + soak | 2, 3 |
| 5 | B2 flip (A/B on CORPLAP-1 and CORPLAP-2) → one release soak → B3 + A4 deletions, retirement table | 3 d | 4 |

## Verification

- Unit: B0 fixtures in `cargo test -p meshharbord --lib` (default build); A0's sweep as `--ignored`
  on hardware hosts; C2's pure tests; the config-surface parity tests for every new key.
- Field: `scripts/rc-ab.sh` on CORPLAP-1 (QSV over the corp VPN — after C1 that pair is TURN, not
  DERP) and CORPLAP-2 (real relay) from neo16; both arms recorded on each FR issue in the FR-59
  table; each field test shown to fail on the current deploy first.
- Fleet: heartbeat counters (`idr_count`, `rate_moves`, `rebuilds`, `shadow_disagree_pct`) read
  with `roomler exec` across Windows/Linux/macOS after every roll; the C2 eviction/revalidation
  counts on the multi-org hosts.
