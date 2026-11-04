// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// @vitest-environment node
//
// Node, not jsdom: jsdom's `crypto` has no `subtle`, and these helpers touch
// nothing but WebCrypto (and a Storage-shaped object the tests provide).
import { describe, it, expect } from 'vitest'
import { toBase64Url } from '@/utils/extauth'
import {
  applyPeerAuthVerdict,
  browserStorage,
  controllerKeyFor,
  controllerPublicKey,
  deviceKeyPoint,
  indexedDbKeyBackend,
  judgePeerAuth,
  newPeerAuthNonce,
  offerAsk,
  withinMs,
  peerAuthAskDisabled,
  peerAuthBadge,
  peerAuthCanVerify,
  peerAuthFingerprint,
  peerAuthTranscript,
  shouldAskPeerAuth,
  singleFingerprint,
  storagePins,
  trustChangedKey,
  verifyPeerAuth,
  type PeerAuthJudgement,
  type PeerAuthVerdict,
} from '@/utils/peerAuth'

// Every vector below is BUILT from bytes, never written as a base64 literal: a
// secret scanner cannot tell a counting sequence, a public curve point or a
// signature from a key (FR-100 P1b's branch was flagged for exactly that).
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

/** The nonce the device's vectors use: bytes 0 to 15, base64url. */
const NONCE = toBase64Url(Uint8Array.from({ length: 16 }, (_, i) => i))

/** The P-256 generator G (FIPS 186-4 D.1.2.3), as a device key carries a point. */
const G = b64(
  Uint8Array.from([
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
    0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
    0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
    0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
    0x68, 0x37, 0xbf, 0x51, 0xf5,
  ]),
)

/**
 * A signature made OUTSIDE both implementations: an OpenSSL 3.5 P-256 key (its
 * private half deleted after signing) over the known-answer transcript below,
 * converted from DER to `r ‖ s`. The device's tests verify the same vector with
 * ring, so the two verifiers are held to one signer neither of them wrote.
 */
const OPENSSL_KEY = b64(
  Uint8Array.from([
    0x04, 0xdf, 0x87, 0x14, 0xf1, 0x2a, 0x41, 0xd2, 0x32, 0x32, 0x0a, 0x24, 0xea, 0xb5, 0x75,
    0x78, 0xc7, 0x4e, 0x63, 0xa3, 0x4d, 0x57, 0xad, 0x90, 0x8a, 0x92, 0xb1, 0xde, 0xca, 0x53,
    0x7a, 0xa5, 0xfb, 0xfd, 0x9a, 0x83, 0x24, 0x1b, 0x9c, 0xdd, 0xd1, 0x06, 0xbd, 0x0c, 0x7e,
    0x0e, 0x0a, 0x87, 0x4e, 0xb1, 0x48, 0x14, 0x0d, 0x14, 0xe3, 0x4a, 0x9e, 0x7c, 0xe3, 0xba,
    0x07, 0xf4, 0xa7, 0x8e, 0xc4,
  ]),
)
const OPENSSL_SIG = toBase64Url(
  Uint8Array.from([
    0x73, 0x2a, 0xa2, 0x53, 0xdc, 0x6e, 0x3a, 0x5b, 0x06, 0xaa, 0x6d, 0x32, 0x37, 0x5a, 0x5e,
    0x08, 0x8e, 0xe1, 0x28, 0x8f, 0x5c, 0x7e, 0x00, 0xd7, 0xba, 0x16, 0x4f, 0x98, 0x9c, 0xc4,
    0x29, 0x6c, 0x38, 0x9f, 0xaa, 0xf2, 0x9c, 0x7b, 0x64, 0xe7, 0x23, 0xb3, 0x97, 0xb2, 0xe3,
    0xb3, 0x46, 0xab, 0x49, 0xb9, 0x74, 0x1b, 0x27, 0x6d, 0x99, 0x71, 0xee, 0x95, 0xb3, 0x71,
    0x83, 0x2d, 0xe5, 0xb3,
  ]),
)

/** The device's known-answer transcript (`a_peer_auth_transcript_matches_its_known_answer`). */
const KAT = () =>
  peerAuthTranscript(
    'answer',
    '66f0c0ffee0000000000000a',
    '66f0c0ffee0000000000000b',
    '66f0c0ffee0000000000000c',
    'sha-256 AA:BB:CC',
    'sha-256 DD:EE:FF',
    NONCE,
  )!

describe('FR-100 P2a: the transcript, as the device frames it', () => {
  it('frames each field with its length, by hand', () => {
    const t = peerAuthTranscript('offer', 'a', 'b', 'c', 'd', 'e', 'f')!
    const want = [
      ...new TextEncoder().encode('meshharbor-peer-auth-v1'),
      0, 5, ...new TextEncoder().encode('offer'),
      ...['a', 'b', 'c', 'd', 'e', 'f'].flatMap((f) => [0, 1, f.charCodeAt(0)]),
    ]
    expect(Array.from(t)).toEqual(want)
  })

  it('matches the device known answer, byte for byte', async () => {
    const t = KAT()
    expect(t.length).toBe(166)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', t))
    expect(hex(digest)).toBe('9e9736b2e6a5db65f5c536bf0cba1042fdca9517c63fd18d6bb8454206e7ac94')
  })

  it('refuses to frame a field too long for its u16 length', () => {
    expect(peerAuthTranscript('answer', 'x'.repeat(70_000), 'b', 'c', 'd', 'e', 'f')).toBeNull()
  })
})

describe('FR-100 P2a: verifying the device signature', () => {
  it('verifies a signature OpenSSL made over the known answer, and nothing else', async () => {
    expect(await verifyPeerAuth(OPENSSL_KEY, KAT(), OPENSSL_SIG)).toBe(true)
    const other = peerAuthTranscript(
      'answer',
      '66f0c0ffee0000000000000a',
      '66f0c0ffee0000000000000b',
      '66f0c0ffee0000000000000d',
      'sha-256 AA:BB:CC',
      'sha-256 DD:EE:FF',
      NONCE,
    )!
    expect(await verifyPeerAuth(OPENSSL_KEY, other, OPENSSL_SIG)).toBe(false)
    expect(await verifyPeerAuth(G, KAT(), OPENSSL_SIG)).toBe(false)
    expect(await verifyPeerAuth(OPENSSL_KEY, KAT(), 'not a signature')).toBe(false)
  })

  it('verifies what a P-256 key signs over a session transcript', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const key = b64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)))
    const t = KAT()
    const sig = toBase64Url(
      new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, t)),
    )
    expect(await verifyPeerAuth(key, t, sig)).toBe(true)
  })

  it('reads a device key only in its one canonical shape', () => {
    expect(deviceKeyPoint(G)?.length).toBe(65)
    const point = deviceKeyPoint(G)!
    const compressed = b64(Uint8Array.from([0x02, ...point.slice(1, 33)]))
    expect(deviceKeyPoint(compressed)).toBeNull()
    expect(deviceKeyPoint(G.replace(/\+/g, '-').replace(/\//g, '_'))).toBeNull()
    expect(deviceKeyPoint(G.replace(/=+$/, ''))).toBeNull()
    expect(deviceKeyPoint('')).toBeNull()
    expect(deviceKeyPoint(undefined)).toBeNull()
  })

  it('shows a key as the device list does', async () => {
    expect(await peerAuthFingerprint(G)).toBe('698b ea63 dc44 a344 663f')
    expect(await peerAuthFingerprint('nope')).toBeNull()
  })

  it('makes a fresh 16-byte nonce each time', () => {
    const a = newPeerAuthNonce()
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect(newPeerAuthNonce()).not.toBe(a)
  })
})

describe('FR-100 P2a: when to ask, and the pins', () => {
  it('asks only an in-org session, on a device that signs and has a key', () => {
    const base = { external: false, rpc: ['exec', 'peer-auth'], peerAuthKey: G, disabled: false }
    expect(shouldAskPeerAuth(base)).toBe(true)
    expect(shouldAskPeerAuth({ ...base, external: true })).toBe(false)
    expect(shouldAskPeerAuth({ ...base, disabled: true })).toBe(false)
    expect(shouldAskPeerAuth({ ...base, rpc: ['exec'] })).toBe(false)
    // Equality, never a prefix.
    expect(shouldAskPeerAuth({ ...base, rpc: ['peer-auth-2'] })).toBe(false)
    expect(shouldAskPeerAuth({ ...base, peerAuthKey: undefined })).toBe(false)
    expect(shouldAskPeerAuth({ ...base, peerAuthKey: 'short' })).toBe(false)
  })

  it('takes an SDP fingerprint only when it names exactly one certificate', () => {
    const line = (hash: string, hexes: string) => `a=fingerprint:${hash} ${hexes}`
    const sdp = (...lines: string[]) => ['v=0', ...lines, ''].join('\r\n')
    expect(singleFingerprint(sdp(line('SHA-256', 'aa:bb')))).toBe('sha-256 AA:BB')
    // The same certificate in every m-section is still one.
    expect(singleFingerprint(sdp(line('sha-256', 'AA:BB'), line('SHA-256', 'aa:bb')))).toBe(
      'sha-256 AA:BB',
    )
    expect(singleFingerprint(sdp())).toBeNull()
    expect(singleFingerprint(sdp(line('sha-256', 'AA:BB'), line('sha-256', 'CC:DD')))).toBeNull()
  })

  it('reads no storage where touching it throws', () => {
    const real = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get() {
        throw new Error('SecurityError')
      },
    })
    try {
      expect(browserStorage()).toBeUndefined()
    } finally {
      if (real) Object.defineProperty(globalThis, 'localStorage', real)
      else delete (globalThis as { localStorage?: unknown }).localStorage
    }
  })

  it('stops asking when told to, and a refusing storage means "ask"', () => {
    expect(peerAuthAskDisabled({ getItem: () => 'off' })).toBe(true)
    expect(peerAuthAskDisabled({ getItem: () => null })).toBe(false)
    expect(
      peerAuthAskDisabled({
        getItem: () => {
          throw new Error('blocked')
        },
      }),
    ).toBe(false)
    expect(peerAuthAskDisabled(undefined)).toBe(false)
  })

  it('keeps one key per user and device, and survives a storage that refuses', () => {
    const backing = new Map<string, string>()
    const storage = {
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => void backing.set(k, v),
    }
    const pins = storagePins(storage)
    expect(pins.get('u1', 'a1')).toBeNull()
    pins.set('u1', 'a1', G)
    expect(pins.get('u1', 'a1')).toBe(G)
    expect(pins.get('u2', 'a1')).toBeNull()
    expect(storagePins(storage).get('u1', 'a1')).toBe(G) // read back from storage

    const refusing = storagePins({
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('blocked')
      },
    })
    refusing.set('u1', 'a1', G)
    expect(refusing.get('u1', 'a1')).toBe(G) // held in memory for the page
  })
})

describe('FR-100 P2a: the verdict on an answer', () => {
  const asked = { nonce: NONCE, offerFingerprint: 'sha-256 AA:BB:CC' }
  const ids = {
    sessionId: '66f0c0ffee0000000000000a',
    agentId: '66f0c0ffee0000000000000b',
    userId: '66f0c0ffee0000000000000c',
    answerFingerprint: 'sha-256 DD:EE:FF',
  }
  const signed = { key: OPENSSL_KEY, sig: OPENSSL_SIG }

  it('not asked: nothing to judge', async () => {
    expect(
      await judgePeerAuth({ ...ids, asked: null, answerPeerAuth: signed, pinned: null }),
    ).toEqual({ kind: 'not-asked' })
  })

  it('first use pins; the same key again is pinned; another key is a change', async () => {
    expect(await judgePeerAuth({ ...ids, asked, answerPeerAuth: signed, pinned: null })).toEqual({
      kind: 'first-use',
      key: OPENSSL_KEY,
    })
    expect(
      await judgePeerAuth({ ...ids, asked, answerPeerAuth: signed, pinned: OPENSSL_KEY }),
    ).toEqual({ kind: 'pinned', key: OPENSSL_KEY })
    expect(await judgePeerAuth({ ...ids, asked, answerPeerAuth: signed, pinned: G })).toEqual({
      kind: 'key-changed',
      key: OPENSSL_KEY,
      pinned: G,
    })
  })

  it('asked but unsigned, or signed over another session, is never accepted as verified', async () => {
    expect(await judgePeerAuth({ ...ids, asked, answerPeerAuth: undefined, pinned: null })).toEqual({
      kind: 'unsigned',
      pinned: null,
    })
    expect(
      await judgePeerAuth({ ...ids, asked, answerPeerAuth: { key: OPENSSL_KEY }, pinned: null }),
    ).toEqual({ kind: 'unsigned', pinned: null })
    // A device this browser has verified before, unsigned now: the verdict
    // says so, for the notice to word.
    expect(
      await judgePeerAuth({ ...ids, asked, answerPeerAuth: undefined, pinned: OPENSSL_KEY }),
    ).toEqual({ kind: 'unsigned', pinned: OPENSSL_KEY })
    // An answer naming no single certificate: the signature may cover one DTLS
    // would not negotiate, so even a signature that would verify never counts.
    expect(
      await judgePeerAuth({
        ...ids,
        answerFingerprint: null,
        asked,
        answerPeerAuth: signed,
        pinned: OPENSSL_KEY,
      }),
    ).toEqual({ kind: 'bad-signature', key: OPENSSL_KEY })
    // Another controller: the same signature does not cover it.
    expect(
      await judgePeerAuth({
        ...ids,
        userId: '66f0c0ffee0000000000000d',
        asked,
        answerPeerAuth: signed,
        pinned: OPENSSL_KEY,
      }),
    ).toEqual({ kind: 'bad-signature', key: OPENSSL_KEY })
  })
})

describe('FR-100 P2a: acting on a verdict', () => {
  const memoryPins = () => {
    const m = new Map<string, string>()
    return {
      get: (u: string, a: string) => m.get(`${u}:${a}`) ?? null,
      set: (u: string, a: string, k: string) => void m.set(`${u}:${a}`, k),
    }
  }
  const judgement = (verdict: PeerAuthVerdict): PeerAuthJudgement => ({
    verdict,
    userId: 'u1',
    agentId: 'a1',
    fingerprint: 'abcd 0123 4567 89ab cdef',
    pinnedFingerprint: null,
  })

  it('pins a first key, refuses a changed key or a bad signature, and lets the rest through', () => {
    const pins = memoryPins()
    expect(applyPeerAuthVerdict({ kind: 'first-use', key: G }, pins, 'u1', 'a1')).toBe('proceed')
    expect(pins.get('u1', 'a1')).toBe(G)
    expect(applyPeerAuthVerdict({ kind: 'pinned', key: G }, pins, 'u1', 'a1')).toBe('proceed')
    expect(applyPeerAuthVerdict({ kind: 'not-asked' }, pins, 'u1', 'a1')).toBe('proceed')
    expect(applyPeerAuthVerdict({ kind: 'unsigned', pinned: G }, pins, 'u1', 'a1')).toBe('proceed')
    expect(
      applyPeerAuthVerdict({ kind: 'key-changed', key: OPENSSL_KEY, pinned: G }, pins, 'u1', 'a1'),
    ).toBe('refuse')
    expect(applyPeerAuthVerdict({ kind: 'bad-signature', key: OPENSSL_KEY }, pins, 'u1', 'a1')).toBe(
      'refuse',
    )
    // A refusal never moves the pin.
    expect(pins.get('u1', 'a1')).toBe(G)
  })

  it('trusts a changed key only after a key-changed refusal, and only that key', () => {
    const pins = memoryPins()
    pins.set('u1', 'a1', G)
    expect(trustChangedKey(null, pins)).toBe(false)
    expect(trustChangedKey(judgement({ kind: 'bad-signature', key: OPENSSL_KEY }), pins)).toBe(false)
    expect(trustChangedKey(judgement({ kind: 'unsigned', pinned: G }), pins)).toBe(false)
    expect(pins.get('u1', 'a1')).toBe(G)
    expect(
      trustChangedKey(judgement({ kind: 'key-changed', key: OPENSSL_KEY, pinned: G }), pins),
    ).toBe(true)
    expect(pins.get('u1', 'a1')).toBe(OPENSSL_KEY)
    expect(pins.get('u2', 'a1')).toBeNull()
  })

  it('says Verified only for a key that proved itself, and Unverified for an unsigned answer', () => {
    expect(peerAuthBadge(null)).toBeNull()
    expect(peerAuthBadge(judgement({ kind: 'not-asked' }))).toBeNull()
    expect(peerAuthBadge(judgement({ kind: 'first-use', key: G }))?.label).toBe('Verified')
    const pinned = peerAuthBadge(judgement({ kind: 'pinned', key: G }))
    expect(pinned?.label).toBe('Verified')
    expect(pinned?.title).toContain('abcd 0123 4567 89ab cdef')
    expect(peerAuthBadge(judgement({ kind: 'unsigned', pinned: null }))?.label).toBe('Unverified')
    expect(peerAuthBadge(judgement({ kind: 'unsigned', pinned: G }))?.title).toContain('before')
    // A refused answer is the error view's to explain, never a toolbar badge.
    expect(peerAuthBadge(judgement({ kind: 'key-changed', key: OPENSSL_KEY, pinned: G }))).toBeNull()
    expect(peerAuthBadge(judgement({ kind: 'bad-signature', key: OPENSSL_KEY }))).toBeNull()
  })

  it('does not ask where it could not verify', () => {
    expect(peerAuthCanVerify()).toBe(true)
    const real = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: { getRandomValues: real?.value?.getRandomValues },
    })
    try {
      expect(peerAuthCanVerify()).toBe(false)
    } finally {
      if (real) Object.defineProperty(globalThis, 'crypto', real)
    }
    expect(peerAuthCanVerify()).toBe(true)
  })
})

describe('FR-100 P2b: the browser signs its offer', () => {
  /** A backend the tests hold: a Map, with knobs for a full store and a racing tab. */
  const mapBackend = (opts: { keeps?: boolean; addThrows?: boolean } = {}) => {
    const m = new Map<string, CryptoKeyPair>()
    return {
      m,
      backend: {
        read: async (u: string) => m.get(u),
        add: async (u: string, p: CryptoKeyPair) => {
          if (opts.addThrows) throw new Error('ConstraintError: another tab kept one')
          if (opts.keeps !== false && !m.has(u)) m.set(u, p)
        },
      },
    }
  }

  it('frames the offer transcript as the device does: an empty answer fingerprint', async () => {
    // The known answer was computed outside both implementations (Perl's
    // Digest::SHA over the same framing); the device's tests pin it too.
    const t = peerAuthTranscript(
      'offer',
      '66f0c0ffee0000000000000a',
      '66f0c0ffee0000000000000b',
      '66f0c0ffee0000000000000c',
      'sha-256 AA:BB:CC',
      '',
      NONCE,
    )!
    expect(t.length).toBe(149)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', t))
    expect(hex(digest)).toBe('3c3da0182f79f04f878356ddbb0983d748b8152a15912a92d095429756428840')
  })

  it('makes one non-extractable key per user and keeps returning it', async () => {
    const { backend } = mapBackend()
    const first = await controllerKeyFor('u1', backend)
    expect(first).not.toBeNull()
    expect(first!.privateKey.extractable).toBe(false)
    const again = await controllerKeyFor('u1', backend)
    expect(await controllerPublicKey(again!)).toBe(await controllerPublicKey(first!))
    const other = await controllerKeyFor('u2', backend)
    expect(await controllerPublicKey(other!)).not.toBe(await controllerPublicKey(first!))
  })

  it('takes the key another tab kept first, and has none where nothing can be kept', async () => {
    const { m, backend } = mapBackend({ addThrows: true })
    const keptByTheOtherTab = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const racing = {
      read: async (u: string) => (m.size === 0 ? undefined : m.get(u)),
      add: async (u: string, p: CryptoKeyPair) => {
        m.set(u, keptByTheOtherTab)
        return backend.add(u, p)
      },
    }
    const got = await controllerKeyFor('u1', racing)
    expect(await controllerPublicKey(got!)).toBe(await controllerPublicKey(keptByTheOtherTab))

    expect(await controllerKeyFor('u1', mapBackend({ keeps: false }).backend)).toBeNull()
    expect(await controllerKeyFor('u1', null)).toBeNull()
    // This spec runs in Node, which has no IndexedDB: no backend, so no key.
    expect(indexedDbKeyBackend()).toBeNull()
  })

  it('signs the offer so the device verifies it, and asks unsigned without a key', async () => {
    const { backend } = mapBackend()
    const pair = (await controllerKeyFor('66f0c0ffee0000000000000c', backend))!
    const ids = {
      nonce: NONCE,
      sessionId: '66f0c0ffee0000000000000a',
      agentId: '66f0c0ffee0000000000000b',
      userId: '66f0c0ffee0000000000000c',
      offerFingerprint: 'sha-256 AA:BB:CC',
    }
    const ask = await offerAsk({ ...ids, pair })
    expect(ask.nonce).toBe(NONCE)
    expect(deviceKeyPoint(ask.key)).not.toBeNull()
    const transcript = peerAuthTranscript(
      'offer',
      ids.sessionId,
      ids.agentId,
      ids.userId,
      ids.offerFingerprint,
      '',
      NONCE,
    )!
    expect(await verifyPeerAuth(ask.key!, transcript, ask.sig!)).toBe(true)
    // Over this offer only: as an answer, or for another session, it fails.
    const asAnswer = peerAuthTranscript(
      'answer',
      ids.sessionId,
      ids.agentId,
      ids.userId,
      ids.offerFingerprint,
      '',
      NONCE,
    )!
    expect(await verifyPeerAuth(ask.key!, asAnswer, ask.sig!)).toBe(false)

    expect(await offerAsk({ ...ids, pair: null })).toEqual({ nonce: NONCE })
  })

  it('gives up on a key store that never answers', async () => {
    const never = new Promise<CryptoKeyPair | null>(() => {})
    expect(await withinMs(never, 20)).toBeNull()
  })
})
