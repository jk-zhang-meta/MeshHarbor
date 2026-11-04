// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-52 P4e — the browser's half of an external session's transport binding.
 *
 * A login the device VERIFIED leaves both ends holding the same OPAQUE session
 * key; neither ever sends it. From it each derives an AppKey, and each side
 * MACs its own DTLS certificate fingerprint under that key:
 *
 * - the browser seals its OFFER, so the device knows the certificate it is
 *   about to pin belongs to whoever proved the password;
 * - the device seals its ANSWER, and this page checks that seal BEFORE
 *   `setRemoteDescription` — so whoever relays the signalling (the server
 *   included) cannot stand in for the device.
 *
 * Every byte here is a wire surface shared with `meshharbord`
 * (`agents/meshharbord/src/external_logins.rs`): the labels, the length
 * prefixes, the field order, the hashes, the encoding. The tests pin the
 * same known-answer vectors the device's tests pin.
 */

const APP_KEY_LABEL = 'meshharbor-extauth-v1 app-key'
const TRANSPORT_LABEL = 'meshharbor-extauth-v1 transport'

/**
 * The password stretching, PINNED: Argon2id, 64 MiB (`memory` is in KiB),
 * three passes, four lanes — the device's `PinnedArgon2` (FR-52 §4-0).
 *
 * ⚠️ A wire surface, like the labels. It equals `@serenity-kit/opaque`'s
 * default today — measured in P3a, and asserted by
 * `extauthKsf.spec.ts` — but a default is something a release can change, and
 * a silent change here would make every device's password stop working at
 * once. So the page says what it means instead of inheriting it.
 */
export const KEY_STRETCHING = {
  'argon2id-custom': { iterations: 3, memory: 65536, parallelism: 4 },
} as const

export type TransportRole = 'offer' | 'answer'

/** Why a fingerprint could not be taken from an SDP. */
export class FingerprintError extends Error {
  constructor(public readonly reason: 'none' | 'ambiguous') {
    super(
      reason === 'none'
        ? 'the SDP names no DTLS certificate'
        : 'the SDP names more than one DTLS certificate',
    )
  }
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) {
    // Only a non-secure context lacks it — and this page needs one anyway
    // (WebRTC does), so this is a deployment error, not a user one.
    throw new Error('WebCrypto is unavailable: the page must be served over https')
  }
  return s
}

const utf8 = new TextEncoder()

/**
 * A copy in a fresh `ArrayBuffer`: WebCrypto's typings accept no view that
 * could sit on a `SharedArrayBuffer`, and copying a caller's key also means
 * zeroing the caller's copy cannot race a pending import.
 */
function own(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes)
}

/**
 * `u16be(len) ‖ bytes` for each field, after the label. Exported for FR-100's
 * transcript (`utils/peerAuth.ts`), which frames its fields the same way: one
 * copy of a wire surface, not two.
 */
export function framed(label: string, ...fields: string[]): Uint8Array<ArrayBuffer> {
  const parts = [utf8.encode(label)]
  for (const f of fields) {
    const bytes = utf8.encode(f)
    // Every field is bounded far below u16 (an id, a role, a fingerprint).
    parts.push(new Uint8Array([(bytes.length >> 8) & 0xff, bytes.length & 0xff]), bytes)
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

/** Base64url, no padding — `@serenity-kit/opaque`'s encoding and the device's. */
export function toBase64Url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The inverse; `null` for anything that is not unpadded base64url. */
export function fromBase64Url(s: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null
  try {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
    const bin = atob(padded)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

/**
 * The SDP's ONE certificate fingerprint, normalised as
 * `lowercase(hash) + " " + UPPERCASE(hex)` — byte for byte what the device
 * computes. Zero, or two distinct ones, is an error: a MAC could cover one
 * certificate while DTLS negotiated the other.
 */
export function sdpFingerprint(sdp: string): string {
  let found: string | null = null
  for (const raw of sdp.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line.startsWith('a=fingerprint:')) continue
    const parts = line.slice('a=fingerprint:'.length).trim().split(/\s+/)
    if (parts.length !== 2) throw new FingerprintError('ambiguous')
    const normalised = `${parts[0]!.toLowerCase()} ${parts[1]!.toUpperCase()}`
    if (found === null) found = normalised
    else if (found !== normalised) throw new FingerprintError('ambiguous')
  }
  if (found === null) throw new FingerprintError('none')
  return found
}

/**
 * `HKDF-SHA512(salt = none, ikm = the OPAQUE session key)`, expanded to 32
 * bytes under the label and the length-prefixed attempt id and principal.
 *
 * An empty salt and RFC 5869's "no salt" are the same thing here: HMAC pads
 * either to a block of zeros.
 */
export async function deriveAppKey(
  sessionKey: Uint8Array,
  attemptId: string,
  principal: string,
): Promise<Uint8Array> {
  const s = subtle()
  const ikm = await s.importKey('raw', own(sessionKey), 'HKDF', false, ['deriveBits'])
  const bits = await s.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-512',
      salt: new Uint8Array(0),
      info: framed(APP_KEY_LABEL, attemptId, principal),
    },
    ikm,
    256,
  )
  return new Uint8Array(bits)
}

async function hmacKey(appKey: Uint8Array, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  return subtle().importKey('raw', own(appKey), { name: 'HMAC', hash: 'SHA-256' }, false, [usage])
}

/** `base64url(HMAC-SHA256(AppKey, label ‖ u16be ‖ role ‖ u16be ‖ fingerprint))`. */
export async function transportMac(
  appKey: Uint8Array,
  role: TransportRole,
  fingerprint: string,
): Promise<string> {
  const tag = await subtle().sign(
    'HMAC',
    await hmacKey(appKey, 'sign'),
    framed(TRANSPORT_LABEL, role, fingerprint),
  )
  return toBase64Url(new Uint8Array(tag))
}

/**
 * Does `mac` seal `fingerprint` for `role` under `appKey`? WebCrypto's
 * `verify` — constant-time, unlike comparing two strings. A MAC that is not
 * even base64url is simply `false`.
 */
export async function verifyTransportMac(
  appKey: Uint8Array,
  role: TransportRole,
  fingerprint: string,
  mac: string,
): Promise<boolean> {
  const tag = fromBase64Url(mac)
  if (!tag) return false
  return subtle().verify(
    'HMAC',
    await hmacKey(appKey, 'verify'),
    tag,
    framed(TRANSPORT_LABEL, role, fingerprint),
  )
}
