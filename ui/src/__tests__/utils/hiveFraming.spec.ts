// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import {
  HEADER,
  MAX_PAYLOAD,
  Reassembler,
  decodeJson,
  encodeFrames,
  encodeJson,
} from '@/utils/hiveFraming'

const BOUNDS = { maxMessageBytes: 1024 * 1024, maxInFlight: 2 }

function roundTrip(message: Uint8Array): Uint8Array {
  const r = new Reassembler(BOUNDS)
  let out: Uint8Array | null = null
  for (const frame of encodeFrames(7, message)) {
    expect(frame.length).toBeLessThanOrEqual(HEADER + MAX_PAYLOAD)
    expect(frame.length).toBeLessThan(65_536)
    const got = r.push(frame)
    if (got instanceof Uint8Array) out = got
    else expect(got).toBeNull()
  }
  expect(out).not.toBeNull()
  return out as Uint8Array
}

describe('hive framing (the browser half of meshharbord/src/hive/framing.rs)', () => {
  it('carries messages of every size', () => {
    for (const len of [0, 1, MAX_PAYLOAD - 1, MAX_PAYLOAD, MAX_PAYLOAD + 1, 300_000]) {
      const message = new Uint8Array(len).map((_, i) => i % 251)
      expect(Array.from(roundTrip(message))).toEqual(Array.from(message))
    }
  })

  it('joins a cut through a multi-byte character before decoding', () => {
    const text = 'ž'.repeat(MAX_PAYLOAD) // two bytes each: cuts land mid-character
    const back = roundTrip(new TextEncoder().encode(text))
    expect(new TextDecoder().decode(back)).toBe(text)
  })

  it('lays the header out exactly as the device does', () => {
    const [frame] = encodeFrames(0x01020304, new Uint8Array([9]))
    expect(Array.from(frame.subarray(0, HEADER))).toEqual([1, 1, 2, 3, 4, 0, 0, 0, 1])
    expect(frame[HEADER]).toBe(9)
  })

  it('completes parts that arrive out of order', () => {
    const message = new Uint8Array(150_000).map((_, i) => i % 7)
    const frames = encodeFrames(1, message).reverse()
    const r = new Reassembler(BOUNDS)
    let out: Uint8Array | null = null
    for (const f of frames) {
      const got = r.push(f)
      if (got instanceof Uint8Array) out = got
    }
    expect(Array.from(out!)).toEqual(Array.from(message))
  })

  it('refuses an oversized message at its first frame', () => {
    const r = new Reassembler({ maxMessageBytes: 100_000, maxInFlight: 2 })
    const frames = encodeFrames(3, new Uint8Array(200_000))
    expect(r.push(frames[0])).toBe('too_large')
    expect(r.inFlight).toBe(0)
  })

  it('calls junk malformed and a bad index inconsistent', () => {
    const r = new Reassembler(BOUNDS)
    expect(r.push(new Uint8Array([1, 2, 3]))).toBe('malformed')
    const f = encodeFrames(9, new Uint8Array([1]))[0]
    f[0] = 2
    expect(r.push(f)).toBe('malformed')
    const g = encodeFrames(9, new Uint8Array([1]))[0]
    new DataView(g.buffer).setUint16(5, 3, false)
    expect(r.push(g)).toBe('inconsistent')
  })

  it('bounds half-sent messages, dropping the oldest', () => {
    const r = new Reassembler(BOUNDS)
    const big = new Uint8Array(2 * MAX_PAYLOAD)
    expect(r.push(encodeFrames(0, big)[0])).toBeNull()
    expect(r.push(encodeFrames(1, big)[0])).toBeNull()
    expect(r.push(encodeFrames(2, big)[0])).toBe('too_many_in_flight')
    expect(r.inFlight).toBe(2)
  })

  it('round-trips JSON, and calls non-JSON null', () => {
    const r = new Reassembler(BOUNDS)
    const [frame] = encodeJson(5, { op: 'hello', v: 1 })
    expect(decodeJson(r.push(frame) as Uint8Array)).toEqual({ op: 'hello', v: 1 })
    expect(decodeJson(new TextEncoder().encode('{nope'))).toBeNull()
  })
})
