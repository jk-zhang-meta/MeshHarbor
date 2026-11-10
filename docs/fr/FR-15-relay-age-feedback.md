# FR-15: Relay age feedback — close the rate loop with the viewer's own clock

Status: **proposed** (evidence collected 2026-08-27, first field session of the FR-1 P7
age pill). Tracking issue: `FR-15` in jk-zhang-meta/MeshHarbor/issues. Child of FR-1; the
successor to FR-10's open decision ("relay drainage needs a signal SCTP doesn't give us").

## Problem

On constrained transports the sender runs **open-loop at the nominal relay clamp**
(~2.5–3 Mbps). When the path's true capacity dips below that — corp TLS middlebox
throttling, TCP RTO stalls on the DERP leg, relay-server backpressure — the excess bytes
queue in layers **below every agent counter** (WG-over-DERP socket, the DERP server's
TCP toward the viewer's egress), and the viewer watches frames get progressively older.
Nothing on the agent can see it; the FR-1 P7 age pill can.

## Evidence (2026-08-27, first age-pill field read — operator + CORPLAP-3 heartbeats + carrier probes)

- **neo16 → CORPLAP-3** (relay, 85 ms): age starts ~60 ms, **climbs to ~120 ms and the
  sluggishness starts with the climb**. +60 ms at 3 Mbps ≈ 22 KB — matches the agent's
  observed inflight excursions (max 26 KB). Mild: path ≈ nominal, queue small but felt.
- **CORPLAP-1 → CORPLAP-3** (both corp-VPN, relay): age **>200 ms sustained, spikes >1000 ms**.
  During that exact session (14:38–14:41Z, AV1 @ 3 Mbps) CORPLAP-3's agent pipeline was
  EMPTY — `bytes_inflight` avg 1.5–9 KB / max 26 KB, `send_wait_max` <10 ms, zero
  skips, `settle_kf_suppressed` active — while the overlay pair's RTT probe bounced
  **111 → 196 → 382 ms**. A 26 KB agent queue cannot make 1000 ms of age: the backlog
  is in the DERP/TCP path, invisible to the sender.
- Same-day agent-side exonerations (encode ~12–15 ms, thrift on) rule out the FR-10
  lump class and the encode pipeline.

## Design

**A. Age over the existing feedback wire.** The viewer already reports
`rc:decodestat {fps, struggling}` once per stats window (rc.188). Add `age_ms` (the
window's average paint-age) and `age_min_ms` (the window's minimum — the path-floor
tracker). Old web sends no age → agent sees absent → loop stays off (back-compat).

**B. Constrained age-loop in the governor.** The agent learns the session's age FLOOR
(min over a 30-window ring — the floor is the path's propagation+decode cost, not
queue; a genuine path change re-baselines in ~30 s). When `age_avg − floor` exceeds
`AGE_SLACK_MS` (70) for ≥2 consecutive windows, treat it as over-rate. Kill switch
`relay_age_feedback` (default ON), constrained-only — direct already has the measured
ceiling + byte gate (and FR-14 will own its episodic holes).

**As implemented (#796), the over-rate response reuses machinery rather than adding a
third rate rule**: the window folds `age_over` into the viewer-rate controller's
`struggling` input (an instant fps-cap cut with no encoder re-open) *and* feeds the
AIMD one congestion sample, so the multiplicative decrease reaches the encoder through
the pump's NORMAL apply arms one frame later — including the FR-10 deferral that keeps
a re-open lump out of the middle of a drag. Recovery is then the AIMD's existing AI
climb plus the viewer-rate controller's slow-start, unchanged.

⚠️ The window tick deliberately does **not** call `take_pending()`: consuming the move
there would mark it applied while the encoder was never told, and the target would
silently diverge from the stream. The AIMD holds the decrease; the pump takes it.

**C. Heartbeat exposure.** `viewer_age_ms` + `viewer_age_floor_ms` in the pump
heartbeat, so field verification reads the loop server-side (`agent_logs`), not just
on the viewer's screen.

Deliberately NOT in scope: shrinking `constrained_queue_ms` (450 ms) — the evidence
shows the queue is mostly BELOW the agent, so tightening the agent's own budget
mostly adds skips without moving the age; revisit only if post-loop residuals point
at the agent again. Also not in scope: intra-refresh (spread-I) encoding — the right
long-term answer to residual IDR cost on thin pipes, but a separate arc.

## P2 — the learned floor is wrong in BOTH directions (field 2026-08-27, 0.4.9)

First field data with the loop live shows `viewer_age_floor_ms` taking values that are
physically impossible for the path, and the loop misbehaving accordingly:

- **Poisoned LOW** — floors of `1`, `2`, `8`, `9`, `10`, `11`, `13`, `15` ms on relays
  whose own carrier RTT is 86–210 ms. A floor of 1 ms cannot exist there. With the
  floor at 1, a perfectly healthy 100 ms window reads as +99 ms of excess and the loop
  fires: `target_bps` is visibly parked at the 1.5 M area floor in windows where
  `send_wait` and `bytes_inflight` say the path was fine. **The loop cuts quality on a
  healthy session.**
- **Poisoned HIGH** — MacBook → CORPLAP-1 learned `viewer_age_floor_ms 1111` while the
  window average was 1 134–13 485 ms. A session that starts congested teaches the loop
  that congestion IS the floor; `min(ring)` can only ever be as good as the best window
  observed, so a uniformly-bad session can never trigger on excess alone.

Mechanism for the low side: the `rc:clock` probe rides the SAME congested DataChannel
as the video it measures, so the midpoint assumption `agent ≈ (t0+t1)/2` is biased
exactly when it matters (request queued behind video, echo prompt). Bias makes computed
ages too small — and `HopStats.add()` silently **drops negative samples**, so the
impossible negatives disappear and the surviving near-zero positives become the floor.

Fixes to design together (none is sufficient alone):
1. **Key the loop on queueing delay, not absolute age** — `age − session_min_age` is
   robust to any constant clock-offset error. Keep absolute age for the HUD.
2. **Sanity-bound the floor against physics the agent already knows** — it logs the
   pair's carrier `rtt_ms` every 5 s. A floor below ~RTT/2, or an absolute age far above
   RTT, is evidence about the clock or the queue, not a valid floor.
3. **Treat a negative age as offset-correction evidence**, not as a dropped sample —
   a frame cannot arrive before it was stamped, so a negative is a direct measurement of
   how wrong the offset is (standard one-way-delay minimum tracking).
4. **Add an absolute over-queue trigger** so a uniformly-bad session still fires.

⚠️ Also unused: `send_wait_avg/max_ms` measures the pipe's refusal to drain directly,
needs no clock and no viewer, and works on both transports — a 907 ms blocked send is
unambiguous congestion. Today it is telemetry only (the goodput stage-1 clamp is
direct-only after the FR-1 P2 relay regression). A long blocked send should be an MD
trigger on constrained. See FR-17 (#799) for why those numbers get so large.

## Acceptance criteria

- [ ] neo16 → CORPLAP-3: age plateaus ≤ ~90 ms during sustained drag (was: climbs to 120);
      no felt sluggishness onset.
- [ ] CORPLAP-1 → CORPLAP-3: no >1000 ms age excursions; sustained age within ~2× that pair's
      floor; heartbeats show `target_bps` stepping DOWN during the viewer's age spikes
      (the loop visibly reacting).
- [ ] A struggling/absent-age viewer (old web) leaves relay behaviour byte-identical
      to 0.4.7.
- [ ] Direct transports untouched (loop gated `constrained`).

## Field log

| date | build | result |
|---|---|---|
| 2026-08-27 | 0.4.7 | Baseline: the two readings above; FR filed. |
| 2026-08-27 | 0.4.8 (#796) | Implemented. Field gate pending: read `viewer_age_ms` / `viewer_age_floor_ms` in the pump heartbeats, and expect `target_bps` to step DOWN while the viewer's age is spiking — that pairing IS the loop working. Agent half needs 0.4.8 on the TARGET (CORPLAP-3), viewer half needs the web deploy. |
| 2026-08-28 | 0.4.11 (#804) | **P2 shipped, both halves live.** Agent `agent-v0.4.11` on CORPLAP-1 + CORPLAP-3; viewer half deployed (`probe_rtt_ms` verified present in the served RC chunk). The floor is now bounded by half the viewer's own probe round trip: sub-physical samples are rejected rather than learned (counted as `viewer_age_implausible`), and an age ≥3× one-way fires regardless of the learned floor. Field gate: `viewer_age_floor_ms` should never again read below ~RTT/2, and `viewer_age_implausible` climbing is the clock-bias signature rather than a slow path. |
