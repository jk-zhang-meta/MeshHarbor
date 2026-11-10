// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-90 P0d-3 — how a viewer peer's messages cross its DataChannel: the
 * browser's half of `agents/meshharbord/src/hive/framing.rs`, byte for byte.
 *
 * One SCTP message may not exceed the negotiated `max_message_size` (65,536
 * bytes by default), and a larger one is not refused — it is silently LOST.
 * So every logical message (one JSON object) travels as binary frames:
 *
 *   byte 0      version (1)
 *   bytes 1..5  message id, u32 big-endian
 *   bytes 5..7  part index, u16 big-endian
 *   bytes 7..9  part count, u16 big-endian (≥ 1)
 *   bytes 9..   a slice of the message's UTF-8 bytes (≤ 60,000)
 *
 * Slices are cut at byte boundaries and joined BEFORE decoding, so a frame
 * never has to hold whole characters.
 */

export const VERSION = 1
export const HEADER = 9
export const MAX_PAYLOAD = 60_000

/** Split one message's bytes into frames. */
export function encodeFrames(id: number, message: Uint8Array): Uint8Array<ArrayBuffer>[] {
  const parts = Math.max(1, Math.ceil(message.length / MAX_PAYLOAD))
  if (parts > 0xffff) throw new Error('message too large to frame')
  const frames: Uint8Array<ArrayBuffer>[] = []
  for (let i = 0; i < parts; i++) {
    const chunk = message.subarray(i * MAX_PAYLOAD, (i + 1) * MAX_PAYLOAD)
    const frame = new Uint8Array(HEADER + chunk.length)
    const view = new DataView(frame.buffer)
    view.setUint8(0, VERSION)
    view.setUint32(1, id >>> 0, false)
    view.setUint16(5, i, false)
    view.setUint16(7, parts, false)
    frame.set(chunk, HEADER)
    frames.push(frame)
  }
  return frames
}

/** One JSON message as frames. */
export function encodeJson(id: number, value: unknown): Uint8Array<ArrayBuffer>[] {
  return encodeFrames(id, new TextEncoder().encode(JSON.stringify(value)))
}

export interface Bounds {
  maxMessageBytes: number
  maxInFlight: number
}

interface PartialMessage {
  parts: number
  got: (Uint8Array | undefined)[]
  bytes: number
  received: number
  order: number
}

/** Why a frame was not accepted — the message it belonged to is lost. */
export type FrameError = 'malformed' | 'too_large' | 'too_many_in_flight' | 'inconsistent'

/** Joins frames back into messages, bounded on every axis a peer could push. */
export class Reassembler {
  private partial = new Map<number, PartialMessage>()
  private nextOrder = 0

  constructor(private bounds: Bounds) {}

  /**
   * Feed one frame. Returns the completed message's bytes, `null` while one
   * is still arriving, or a {@link FrameError} when a message was lost.
   */
  push(frame: Uint8Array): Uint8Array | null | FrameError {
    if (frame.length < HEADER || frame[0] !== VERSION) return 'malformed'
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
    const id = view.getUint32(1, false)
    const index = view.getUint16(5, false)
    const parts = view.getUint16(7, false)
    const payload = frame.subarray(HEADER)
    if (parts === 0 || index >= parts) {
      this.partial.delete(id)
      return 'inconsistent'
    }
    const maxParts = Math.max(1, Math.ceil(this.bounds.maxMessageBytes / MAX_PAYLOAD))
    if (parts > maxParts || payload.length > MAX_PAYLOAD) {
      this.partial.delete(id)
      return 'too_large'
    }
    if (parts === 1) {
      return payload.length > this.bounds.maxMessageBytes ? 'too_large' : payload.slice()
    }
    let evicted = false
    if (!this.partial.has(id) && this.partial.size >= this.bounds.maxInFlight) {
      let oldest: number | undefined
      let oldestOrder = Infinity
      for (const [k, p] of this.partial) {
        if (p.order < oldestOrder) {
          oldestOrder = p.order
          oldest = k
        }
      }
      if (oldest !== undefined) {
        this.partial.delete(oldest)
        evicted = true
      }
    }
    let entry = this.partial.get(id)
    if (!entry) {
      entry = { parts, got: new Array(parts), bytes: 0, received: 0, order: this.nextOrder }
      this.partial.set(id, entry)
    }
    this.nextOrder++
    if (entry.parts !== parts) {
      this.partial.delete(id)
      return 'inconsistent'
    }
    if (entry.got[index] === undefined) {
      entry.got[index] = payload.slice()
      entry.bytes += payload.length
      entry.received++
    }
    if (entry.bytes > this.bounds.maxMessageBytes) {
      this.partial.delete(id)
      return 'too_large'
    }
    if (entry.received < entry.parts) return evicted ? 'too_many_in_flight' : null
    this.partial.delete(id)
    const out = new Uint8Array(entry.bytes)
    let at = 0
    for (const part of entry.got) {
      if (part) {
        out.set(part, at)
        at += part.length
      }
    }
    return out
  }

  /** Messages half-received now. Tests only. */
  get inFlight(): number {
    return this.partial.size
  }
}

/** Decode a completed message as JSON; `null` for anything that is not. */
export function decodeJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}
