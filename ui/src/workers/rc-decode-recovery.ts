// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-131 P2, a port of roomler-ai's FR-135 R1 — a decoder that fails after its
 * first frame recovers in place.
 *
 * Before R1 the composable answered that failure by stopping the worker. On a
 * data-channel session nothing else carries pixels, so the picture froze until
 * the media watchdog re-created the session: 9.4 s and 10.2 s from the error to
 * the next session, measured in upstream FR-132 §8. The bound is 500 ms to the
 * next paint (upstream FR-135 §3.5, §6.8; here FR-131 AC2).
 *
 * The worker now builds a new decoder, asks for a key frame, and the
 * leading-delta gate drops deltas until it lands. It builds a new one because
 * WebCodecs closes a `VideoDecoder` when it errors: `reset()` on it throws
 * `InvalidStateError`, so a reset is not available on the path that matters.
 *
 * This module holds only the decision, so the rules can be tested without
 * WebCodecs:
 *
 * ```
 * decoding ──failure──▶ recovering ──output──▶ decoding
 *                        │    ▲
 *                        └────┘ another failure, within the budget
 * ```
 *
 * ⚠️ Three failures are not this module's to answer, and `onFailure` returns
 * false for them so the worker reports the error as before:
 * - Before the first frame. There it means the browser's probe was wrong for
 *   this stream, and the composable bans the transport and renegotiates. A new
 *   decoder would hide that and leave a black page.
 * - With the per-browser kill switch set (`meshharbor-rc-decode-recover=0`).
 * - Past the budget. A stream this decoder cannot take fails again on every key
 *   frame, so the session goes back to the watchdog's path, which re-creates it.
 */

/** Rebuilds allowed inside `DECODE_RECOVER_WINDOW_MS`. The agent answers at most
 *  two key-frame asks a second, so a stream that kills every decoder uses these
 *  up in a second or two. A fault that recurs more slowly than this keeps
 *  recovering, at a short freeze each time instead of a new session. */
export const DECODE_RECOVER_MAX_ATTEMPTS = 3
export const DECODE_RECOVER_WINDOW_MS = 10_000

export interface DecodeRecovered {
  /** From the failure that began this outage to the first frame after it. */
  ms: number
  /** Decoders built during this outage: more than one means a new decoder
   *  failed before it produced a frame. */
  attempts: number
}

/** A decode worker's recovery state for its session. */
export interface DecodeRecovery {
  /** The session's flag from the main thread. Sticky: a message that omits it
   *  (the idempotent visible-canvas re-init) leaves it as it was. Off until the
   *  main thread says otherwise, like the worker's other session flags. */
  setEnabled(on: boolean): void
  /** The session's video channel is unordered (`meshharbor-rc-unordered-video=1`).
   *  Sticky, like the flag above. */
  setUnorderedChannel(on: boolean): void
  /** A chunk gap. True: the deltas behind it wait at the gate for a key frame.
   *  False: they decode with artefacts, as before R1, and the picture moves.
   *  That is the switch's old path, and the unordered channel's only path: a
   *  lost packet there kills its chunk, which is routine, and at 1 % loss a key
   *  frame rarely survives whole (upstream FR-135 §6.8). A gate waiting for one holds the
   *  picture still until the watchdog re-creates the session. */
  gapClosesGate(): boolean
  /** The decoder failed. True: build a new decoder, ask for a key frame, and do
   *  not report the error as fatal. False: report it as before. */
  onFailure(framesDecoded: number, nowMs: number): boolean
  /** A frame came out of the decoder. Returns the outage it ended, once. */
  onOutput(nowMs: number): DecodeRecovered | null
  /** Decoders built during the outage in progress; 0 when there is none. */
  readonly attempts: number
}

export function createDecodeRecovery(): DecodeRecovery {
  let enabled = false
  let unorderedChannel = false
  // Every rebuild still inside the window, oldest first.
  let rebuilds: number[] = []
  let outageSince: number | null = null
  let attempts = 0
  return {
    setEnabled(on: boolean): void {
      enabled = on
    },
    setUnorderedChannel(on: boolean): void {
      unorderedChannel = on
    },
    gapClosesGate(): boolean {
      return enabled && !unorderedChannel
    },
    onFailure(framesDecoded: number, nowMs: number): boolean {
      if (!enabled || framesDecoded === 0) return false
      rebuilds = rebuilds.filter((t) => nowMs - t < DECODE_RECOVER_WINDOW_MS)
      if (rebuilds.length >= DECODE_RECOVER_MAX_ATTEMPTS) return false
      rebuilds.push(nowMs)
      if (outageSince === null) outageSince = nowMs
      attempts++
      return true
    },
    onOutput(nowMs: number): DecodeRecovered | null {
      if (outageSince === null) return null
      const recovered = { ms: nowMs - outageSince, attempts }
      outageSince = null
      attempts = 0
      return recovered
    },
    get attempts() {
      return attempts
    },
  }
}
