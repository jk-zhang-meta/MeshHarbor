// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// @vitest-environment node
//
// Node, not jsdom: jsdom's `crypto` has no `subtle`, and these helpers touch
// nothing but WebCrypto.
import { describe, it, expect } from 'vitest'
import {
  FingerprintError,
  deriveAppKey,
  fromBase64Url,
  sdpFingerprint,
  toBase64Url,
  transportMac,
  verifyTransportMac,
} from '@/utils/extauth'

/** The vectors the DEVICE's tests pin too (`agents/meshharbord/src/external_logins.rs`). */
const FP =
  'sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3C:5F:03:24:5E:E5:66:1C:20:D2:28:A8'
const OTHER_FP =
  'sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00'

const bytes = (n: number) => Uint8Array.from({ length: n }, (_, i) => i)
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

function sdpWith(...fingerprints: string[]): string {
  let sdp = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n'
  fingerprints.forEach((fp, mid) => {
    sdp += `m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:${mid}\r\na=fingerprint:${fp}\r\n`
  })
  return sdp
}

describe('FR-52 transport binding — the browser half', () => {
  it('derives the AppKey the device derives (HKDF known answer)', async () => {
    const key = await deriveAppKey(bytes(64), 'a1b2c3d4e5f60718293a4b5c6d7e8f90', '665f1c2a9b3e4d5f6a7b8c9d')
    expect(hex(key)).toBe('7718aa60e955c361d08a866cc97778ce06006d767a0d0d5503510b98cde651e5')
  })

  it('moving bytes between the two fields changes the key (length prefixes, not separators)', async () => {
    const ikm = new Uint8Array(64).fill(7)
    const a = await deriveAppKey(ikm, 'ab', 'cd')
    const b = await deriveAppKey(ikm, 'a', 'bcd')
    expect(hex(a)).not.toBe(hex(b))
  })

  it('MACs a fingerprint exactly as the device does (HMAC known answers)', async () => {
    expect(await transportMac(bytes(32), 'offer', FP)).toBe('9C7Hj7E39lXWd1VP-ttMoR3G39CrYJLXbaNjkGJ4W5w')
    expect(await transportMac(bytes(32), 'answer', FP)).toBe('dvUftw510jDyQn0j9c6XslWOoB19z-QTW3FUgUCz6rY')
  })

  it('verifies only the right role, key and certificate', async () => {
    const key = bytes(32)
    const answer = 'dvUftw510jDyQn0j9c6XslWOoB19z-QTW3FUgUCz6rY'
    expect(await verifyTransportMac(key, 'answer', FP, answer)).toBe(true)
    // The offer's tag replayed as the answer's.
    expect(await verifyTransportMac(key, 'answer', FP, await transportMac(key, 'offer', FP))).toBe(false)
    // Another login's key.
    expect(await verifyTransportMac(new Uint8Array(32).fill(8), 'answer', FP, answer)).toBe(false)
    // A genuine tag over a different certificate: a swapped answer.
    expect(await verifyTransportMac(key, 'answer', OTHER_FP, answer)).toBe(false)
    // Not a tag at all.
    expect(await verifyTransportMac(key, 'answer', FP, 'not base64url!')).toBe(false)
    expect(await verifyTransportMac(key, 'answer', FP, '')).toBe(false)
  })

  it('normalises the fingerprint and insists on exactly one certificate', () => {
    const [hash, hexPart] = FP.split(' ') as [string, string]
    const shouted = `${hash.toUpperCase()} ${hexPart.toLowerCase()}`
    expect(sdpFingerprint(sdpWith(shouted, FP))).toBe(FP)
    expect(() => sdpFingerprint(sdpWith(FP, OTHER_FP))).toThrow(FingerprintError)
    expect(() => sdpFingerprint(sdpWith())).toThrow(FingerprintError)
    for (const malformed of ['sha-256', 'sha-256 AA:BB trailing']) {
      expect(() => sdpFingerprint(sdpWith(malformed))).toThrow(FingerprintError)
    }
  })

  it('round-trips base64url without padding, and refuses anything else', () => {
    const b = Uint8Array.from([0xfb, 0xff, 0xfe, 0x00, 0x01])
    expect(toBase64Url(b)).toBe('-__-AAE')
    expect(fromBase64Url('-__-AAE')).toEqual(b)
    expect(fromBase64Url('+//+AAE=')).toBeNull()
  })
})
