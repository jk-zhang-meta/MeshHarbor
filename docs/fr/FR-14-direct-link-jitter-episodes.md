# FR-14: Direct-link jitter episodes — the AIMD sawtooth on VPN-churning links

Status: **design** (evidence collected 2026-08-27). Tracking issue: `FR-14` in
jk-zhang-meta/MeshHarbor/issues. Child of FR-1 (same program: RustDesk-parity drag
smoothness); split out because it is direct-path-specific where FR-10 was
relay-specific.

## Problem

A direct-carrier session over an *unstable* underlay (corp-VPN churn, Wi-Fi
roaming) alternates between two bad states: **lag lumps** (a send stall arrives
while the pipe is full at nominal rate) and **blur phases** (the rate controller
crashes to the area floor and takes ~70 s to climb back). Steady links don't see
either; relay links are already protected (FR-10). The user-felt verdict on the
reference pair: "CORPLAP-1's screen from neo16 is a bit sluggish".

## Evidence (2026-08-27, CORPLAP-1 as agent, neo16 viewing, direct profile 1920×1200@60, hevc_qsv)

From `agent_logs` FFmpeg-pump heartbeats (2 s windows), hour-bucketed:

| window | n | target_bps | bytes_inflight max | send_wait_max | skips (cum) |
|---|---|---|---|---|---|
| 11:00Z | 1176 | avg 12.03 M, pegged at nominal | **164,770 B** | **56.8 ms** | 73 |
| 12:00Z | 499 | avg 5.86 M, **min 1.50 M = area floor** | 124,857 B | 48.9 ms | 169 |

- 26 `overlay: network change — re-asserting peer routes` events in those two
  hours — the corp VPN was churning the whole session.
- Same agent, same day, on the **relay** profile (13:00Z): clean — inflight
  ≤ 28 KB, `settle_kf_suppressed` active, send_wait_max 2.2 ms. The defect is
  direct-only.
- `avg_encode_ms` ≈ 10, `avg_capture_ms` ≈ 2–5 throughout: the encode pipeline
  is not the limiter.

## Root cause (mechanism)

Measured-ceiling v2 (FR-1 P2) samples only **blocked** sends (≥ 10 ms
serialization). An episodic-stall link produces samples only *during* an
episode; between episodes the pipe drains sub-ms, so no samples arrive, the
60 s TTL expires the estimate, the stage-1 clamp releases, and AIMD re-climbs
to nominal (12 M). The next stall then lands on a full pipe — the 150 ms direct
queue budget ≈ 164 KB of queued video = a visible multi-hundred-ms lump — and
the MD run crashes the target toward the floor (1.5 M), which the AI ramp
(+ceiling/16 per 5 s) needs ~70 s to undo. The estimator designed for
*continuously* constrained pipes has no memory for *episodically* constrained
ones.

## Design directions (choose at implementation time; all direct-only, each behind its own config-surface kill switch)

- **A. Stall-episode memory**: when an MD run reaches the floor (or N MDs
  within M s), latch `episode_ceiling := max(goodput_at_crash, 2×floor)` and
  decay it back toward nominal slowly (e.g. +5% per 30 s). The link's crash
  level becomes the soft ceiling instead of being forgotten.
- **B. Adaptive queue budget**: when send-wait spikes repeat (≥ K spikes
  ≥ 20 ms within 60 s), tighten `direct_queue_ms` 150 → 75 until quiet for
  5 min. Caps the lump size rather than the rate.
- **C. Goodput TTL with decay**: replace the hard 60 s expiry with a widening
  clamp (confidence decay), so an episodic link keeps a soft memory of its last
  measured goodput.

A is the strongest candidate (attacks the re-climb), B the cheapest (attacks
the lump), and they compose.

## Acceptance criteria

- [ ] On a VPN-churning direct pair (CORPLAP-1-class), `target_bps` never crashes
      to the area floor during a 30-min drag session (no min=floor heartbeat
      windows like 12:00Z above).
- [ ] `bytes_inflight` p99 < 80 KB on that pair (was: max 164 KB).
- [ ] Field: dragging on CORPLAP-1-from-neo16 *during* VPN churn shows no
      multi-hundred-ms lumps.
- [ ] Relay/constrained behaviour byte-identical (everything gated
      `!constrained`).

## Field log

| date | build | result |
|---|---|---|
| 2026-08-27 | 0.4.5 | Baseline evidence above; FR filed. |
