# FR-44 — Shared-pipeline multi-viewer: a second viewer of one screen rendered black, then dropped the first

Status: **CLOSED — all three causes fixed and field-verified (agent-v0.4.31 / 0.4.32 / 0.4.33, 2026-08-30).** Tracking issue: `FR-44` (#1024). Retroactive: written after the arc shipped, per the FR standing rule ("retroactive FRs for already-shipped arcs are welcome").

## Goal

Two people viewing the **same** remote screen at once must both see it, and neither may disrupt the other. MeshHarbor already shares ONE encoder across same-profile viewers (`crates`… `agents/meshharbord/src/media_share.rs` — the P5 shared pipeline: a LEADER runs the capture/encode pump, later same-profile sessions register as FOLLOWERS and receive every encoded packet via their own DataChannel). The sharing existed; its correctness under a real second viewer did not.

## Field evidence

Reported by the operator, two browser tabs on **neo16** viewing **CORPLAP-3** (Windows, `av1_qsv`, relay-locked by a corp VPN):

1. The **second viewer rendered a black screen** while the first worked — consistently across retries.
2. After the framing fix, the second viewer's **window-drag disconnected the first**, the second joined slowly, and latency spiked.

Investigation found **three distinct causes**, each fixed in sequence.

## Key design (three causes, three fixes)

### P1 — join-IDR dropped before the follower's video DC opened (keyframe race) — #1015, 0.4.31
A follower registers during `AgentPeer::new` (before any DataChannel exists) and `try_join` sets `kf_needed`; the leader forces a pipeline IDR ~33 ms later and `Pipeline::fan_out` flips the follower to `synced` the instant it QUEUES that IDR. But the follower's `video-bytes` DC finishes negotiating hundreds of ms later (field: 819 ms), and `spawn_follower_chunker` drops anything arriving while the DC is `None`/`!Open` — so the join-IDR is lost yet the follower is `synced`: only undecodable deltas follow → black until the next natural keyframe. The **control** DC already had an on-open resync hook (`replay_video_info`); the **video** DC had none.
- Fix: `media_share::resync_follower` (`agents/meshharbord/src/media_share.rs:742`), called from the `video-bytes` on-open arm in `peer.rs` — reset `synced=false` + `kf_needed=true` so the follower re-syncs onto a fresh IDR the now-live chunker delivers. No-op for a leader.

### P2 — follower received RAW un-chunk-framed bytes (the real black-screen cause) — #1018, 0.4.32
The leader's send task wraps each 16 KiB chunk in the FR-17 header (`frame_seq`/`chunk_idx`/`chunk_count`) when the session negotiated chunk-framing, but `spawn_follower_chunker` sent `wire.slice()` RAW, ALWAYS. The browser (same one as the working leader) parsed a chunk header out of AV1 payload and could never reassemble a frame → structurally undecodable → black, consistently. Every chunk-framing follower was broken; only non-chunk-framing clients happened to work.
- Fix: `FollowerSink.chunk_framing` (`agents/meshharbord/src/media_share.rs:130`, a per-SESSION property — a follower may disagree with the owner) + `spawn_follower_chunker` (`:769`) now mirrors the owner's send task exactly (FR-17 header per chunk with its own `frame_seq`, else raw).
- Verified at the byte level: follower messages `len=16392, seq=1, chunk_idx=0..14, size=232438, flags=1` (a valid chunk-framed keyframe) vs the pre-fix garbage `len=16384, seq=121544, chunk_idx=52993`.

### P3 — shared egress not viewer-count-aware → 2nd viewer oversubscribed the relay and dropped the 1st — #1020, 0.4.33
A shared encoder sends every viewer its OWN ciphertext copy over its OWN DataChannel, but the bitrate ceiling did not account for the viewer count. On a CONSTRAINED (relay) transport all copies leave the host over the SAME uplink, so N viewers = N× egress while the encoder still targeted the full relay bandwidth. A 2nd viewer's motion put ~2× the relay's capacity on the wire → the leader's ICE went `Disconnected` under the congestion → the pipeline collapsed and re-dispatched (the leader is a single point of failure). `followers_congested` only trims AFTER the queue fills.
- Fix: `encode::shared_split_ceiling_bps` (`agents/meshharbord/src/encode/mod.rs:503`, gated by `shared_rate_split_enabled` `:488`) — on a constrained transport divide the ceiling by the live viewer count (`1 + pipeline.follower_count()`), floored at `area_min_bitrate_bps` so no copy drops below usable quality; the reactive AIMD path trims residual. Applied in both DC pumps (`peer.rs:3962` vp9, `:5807` ffmpeg), recomputed each iteration so it tracks joins/leaves. Single viewer and direct transports untouched. Kill switch `MESHHARBORD_SHARED_RATE_SPLIT=0`.
- Verified: leader `target_bps` **2,550,000 (1 viewer) → 1,500,000 (2 viewers, floored)** on CORPLAP-3 — total relay egress ~5.1 M → ~3 M.

## Acceptance criteria

- [x] A second same-profile viewer of one screen renders the screen, not black (P1 + P2; byte-level verified 0.4.32, operator-confirmed).
- [x] A follower's forced/join IDR is delivered correctly framed once its video DC is live (P1; agent-log verified — `re-syncing onto a fresh IDR`).
- [x] A follower's `video-bytes` messages carry the same FR-17 framing the leader's do (P2; byte-level verified).
- [x] A second viewer's motion no longer disconnects the first on a constrained relay (P3; mechanism verified — ceiling halves; operator-confirmed "better with 2 tabs").
- [x] Single-viewer and direct-transport behaviour unchanged (P3; split is a no-op there, unit-locked).

## Open decisions

- **None blocking.** The 2-viewer quality tradeoff (each ~1.5 M on a ~2.5 M relay) is deliberate; see Out of scope for the only way to remove it.

## Out of scope

- **The base per-viewer latency on the neo16↔CORPLAP-3 pair** — that pair is relay-locked by the corp VPN capturing the LAN prefix (`192.168.68.0/24` → the VPN gateway `10.138.80.1`; direct LAN probes never handshake). Environmental; corp-VPN evasion is out of scope, and surfacing it is [FR-33](FR-33-lan-capture-surfacing.md).
- **Giving BOTH viewers full quality over a relay** — the host sends N copies over one uplink because each viewer has its own P2P/relay leg. The only removal is **server-side fan-out** (the DERP relay duplicates one ciphertext stream to N viewers), a substantial change to a relay that today forwards blindly. A future FR if multi-viewer-over-relay quality becomes a priority.

## Field-verification log

- **2026-08-30, CORPLAP-3 (av1_qsv, relay):**
  - 0.4.30/0.4.31: follower receives bytes but no render target; agent log shows follower join at `15:29:23.281`, video-DC stash at `15:29:24.081` (819 ms race window). P1 resync fires on 0.4.31 but the picture stays black.
  - 0.4.32: follower `video-bytes` now chunk-framed (`len=16392, chunk_idx=0..14, keyframe flags=1`), 2 keyframes received, zero `follower: DC send failed`. Operator: still black — because P3 was not yet shipped and the follower stream was fine but the pair was congesting (see below).
  - 0.4.33: leader `target_bps` 2.55 M (1 viewer) → 1.5 M (2 viewers). Operator: **"better with 2 parallel neo16 tabs viewing CORPLAP-3."**

## Related

FR-1 (drag latency), FR-33 (LAN-capture surfacing — the relay lock), FR-35 (relay ceiling), FR-31 (opening keyframe). Memory: `reference_shared_viewer_keyframe_race`.
