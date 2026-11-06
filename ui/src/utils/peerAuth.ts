// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-100 P2a — the browser's half of the device's answer signature.
 *
 * When the device advertises `peer-auth` and its row carries a key, this page
 * asks: a fresh nonce rides `rc:sdp.offer`. The device signs its answer over
 * the session's transcript with its device key (P1b), and this page checks the
 * signature BEFORE `setRemoteDescription`, as FR-52's external mode checks its
 * MAC. The key that signed is pinned on first use, per user and device, in this
 * browser: an answer later signed by another key, or by none it can verify, is
 * from a device this browser has not met.
 *
 * Every byte of the transcript is a wire surface shared with the device
 * (`crates/remote_control/src/signaling.rs`, `peer_auth_transcript`): the label,
 * the length prefixes, the field order, the encodings. The tests pin the same
 * known answer, and verify a signature made outside both implementations.
 */
import { framed, fromBase64Url, sdpFingerprint, toBase64Url } from '@/utils/extauth'

/** The label every peer-auth signature is scoped by. Part of the wire. */
export const PEER_AUTH_LABEL = 'meshharbor-peer-auth-v1'

export type PeerAuthRole = 'offer' | 'answer'

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) throw new Error('WebCrypto is unavailable: the page must be served over https')
  return s
}

/**
 * The bytes a peer-auth signature covers: the label, then each field as
 * `u16be(len) ‖ bytes`, in this order: role, session id, agent id, user id,
 * the offer's DTLS fingerprint, the answer's, the nonce. `null` when a field
 * is too long to frame, which no well-formed input is.
 */
export function peerAuthTranscript(
  role: PeerAuthRole,
  sessionId: string,
  agentId: string,
  userId: string,
  offerFingerprint: string,
  answerFingerprint: string,
  nonce: string,
): Uint8Array<ArrayBuffer> | null {
  const fields = [role, sessionId, agentId, userId, offerFingerprint, answerFingerprint, nonce]
  const utf8 = new TextEncoder()
  if (fields.some((f) => utf8.encode(f).length > 0xffff)) return null
  return framed(PEER_AUTH_LABEL, ...fields)
}

/** A fresh nonce: 16 random bytes, base64url without padding. */
export function newPeerAuthNonce(): string {
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(16)))
}

/**
 * The SDP's one DTLS fingerprint (`sdpFingerprint`), or `null` when it names
 * none or two. The device takes its fingerprints the same way, and signs
 * nothing it cannot take one from.
 */
export function singleFingerprint(sdp: string): string | null {
  try {
    return sdpFingerprint(sdp)
  } catch {
    return null
  }
}

/**
 * A device key as the hello carries it (standard, padded base64 of a 65-byte
 * uncompressed P-256 point) decoded, or `null` for anything else: the device's
 * `peer_auth_key_is_well_formed`, in the browser.
 */
export function deviceKeyPoint(key: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof key !== 'string' || key.length !== 88 || !/^[A-Za-z0-9+/]+={0,2}$/.test(key)) {
    return null
  }
  let bin: string
  try {
    bin = atob(key)
  } catch {
    return null
  }
  if (bin.length !== 65 || bin.charCodeAt(0) !== 0x04) return null
  const out = new Uint8Array(65)
  for (let i = 0; i < 65; i++) out[i] = bin.charCodeAt(i)
  // One key, one spelling.
  if (btoa(bin) !== key) return null
  return out
}

/**
 * Does `sig` (base64url, the fixed 64-byte `r ‖ s`) verify over `transcript`
 * under `key` (a device key as the hello carries it)? WebCrypto's ECDSA
 * P-256 / SHA-256, the device's ring `ECDSA_P256_SHA256_FIXED`. Anything that
 * is not even well formed is simply `false`.
 */
export async function verifyPeerAuth(
  key: string,
  transcript: Uint8Array<ArrayBuffer>,
  sig: string,
): Promise<boolean> {
  const point = deviceKeyPoint(key)
  const sigBytes = fromBase64Url(sig)
  if (!point || !sigBytes || sigBytes.length !== 64) return false
  try {
    const k = await subtle().importKey('raw', point, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'verify',
    ])
    return await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sigBytes, transcript)
  } catch {
    // A point that is not on the curve: WebCrypto refuses to import it.
    return false
  }
}

/**
 * A device key as a person reads it: the first 10 bytes of the point's
 * SHA-256, lowercase hex in groups of four. The device list shows the same
 * string (`peer_auth_fingerprint`), so a person can compare them.
 */
export async function peerAuthFingerprint(key: string): Promise<string | null> {
  const point = deviceKeyPoint(key)
  if (!point) return null
  const digest = new Uint8Array(await subtle().digest('SHA-256', point))
  const hex = Array.from(digest.slice(0, 10), (b) => b.toString(16).padStart(2, '0')).join('')
  return hex.match(/.{4}/g)!.join(' ')
}

/**
 * Can this page verify a signature at all? WebCrypto's `subtle` exists only in
 * a secure context, and WebRTC does not need one: a self-hosted server on
 * `http://<lan address>` runs sessions without it. A page that cannot verify
 * must not ask, or every answer it asked for would read as a bad signature.
 */
export function peerAuthCanVerify(): boolean {
  try {
    return typeof globalThis.crypto?.subtle?.verify === 'function'
  } catch {
    return false
  }
}

/**
 * Should this session ask the device to sign its answer? Only an in-org
 * session (an outsider's is bound by FR-52's MAC instead), only from a device
 * that says it signs (`peer-auth`, matched by equality) and whose row carries
 * a well-formed key, and not when this browser has been told not to ask.
 */
export function shouldAskPeerAuth(opts: {
  external: boolean
  rpc: unknown
  peerAuthKey: unknown
  disabled: boolean
}): boolean {
  if (opts.external || opts.disabled) return false
  const rpc = Array.isArray(opts.rpc) ? opts.rpc : []
  return rpc.some((w) => w === 'peer-auth') && deviceKeyPoint(opts.peerAuthKey) !== null
}

/** The kill switch: `localStorage['meshharbor.peerAuth.ask'] = 'off'` stops asking. */
export const PEER_AUTH_ASK_KEY = 'meshharbor.peerAuth.ask'

export function peerAuthAskDisabled(storage: Pick<Storage, 'getItem'> | undefined): boolean {
  try {
    return storage?.getItem(PEER_AUTH_ASK_KEY) === 'off'
  } catch {
    return false
  }
}

/**
 * This origin's `localStorage`, or `undefined` where reading the property
 * itself throws (blocked site data does exactly that, before any `getItem`).
 */
export function browserStorage(): Storage | undefined {
  try {
    return globalThis.localStorage ?? undefined
  } catch {
    return undefined
  }
}

/** This browser's pins: one device key per (user, device). */
export interface PeerAuthPins {
  get(userId: string, agentId: string): string | null
  set(userId: string, agentId: string, key: string): void
}

const PINS_KEY = 'meshharbor.peerAuth.pins.v1'

/**
 * The pins in `localStorage`. Public keys only, so nothing here is secret;
 * what matters is that they are this browser's own memory of each device. A
 * storage that refuses (a private window, blocked site data) leaves an
 * in-memory map for the page's lifetime: every device is then first-use again
 * next time, never a false alarm.
 */
export function storagePins(storage: Pick<Storage, 'getItem' | 'setItem'> | undefined): PeerAuthPins {
  const memory = new Map<string, string>()
  const read = (): Record<string, string> => {
    try {
      const raw = storage?.getItem(PINS_KEY)
      const parsed: unknown = raw ? JSON.parse(raw) : {}
      return parsed && typeof parsed === 'object' ? (parsed as Record<string, string>) : {}
    } catch {
      return {}
    }
  }
  const id = (userId: string, agentId: string) => `${userId}:${agentId}`
  return {
    get(userId, agentId) {
      const k = id(userId, agentId)
      const v = memory.get(k) ?? read()[k]
      return typeof v === 'string' ? v : null
    },
    set(userId, agentId, key) {
      const k = id(userId, agentId)
      memory.set(k, key)
      try {
        const all = read()
        all[k] = key
        storage?.setItem(PINS_KEY, JSON.stringify(all))
      } catch {
        /* the in-memory pin still holds for this page */
      }
    },
  }
}

/** What this page concluded about a session's answer. */
export type PeerAuthVerdict =
  /** The page did not ask (an older device, an outsider's session, switched off). */
  | { kind: 'not-asked' }
  /** Verified, by a key this browser had not pinned for this device: now pinned. */
  | { kind: 'first-use'; key: string }
  /** Verified, by the key this browser pinned. */
  | { kind: 'pinned'; key: string }
  /** Verified, but by ANOTHER key than the one pinned: not the device this browser met. */
  | { kind: 'key-changed'; key: string; pinned: string }
  /**
   * Asked, and the answer carries no signature. `pinned` is the key this
   * browser holds for the device, if any: a device that has signed before
   * and now does not is worth saying so about.
   */
  | { kind: 'unsigned'; pinned: string | null }
  /** A signature that does not verify over this session's transcript. */
  | { kind: 'bad-signature'; key: string }

/** The answer's `peer_auth`, if it is shaped like one. */
function answerBinding(v: unknown): { key: string; sig: string } | null {
  if (!v || typeof v !== 'object') return null
  const { key, sig } = v as { key?: unknown; sig?: unknown }
  return typeof key === 'string' && typeof sig === 'string' ? { key, sig } : null
}

/**
 * Judge a session's answer. `asked` is what this page sent with its offer, or
 * `null` when it did not ask. `answerFingerprint` is `null` when the answer
 * names no single certificate: a signature then covers a certificate DTLS
 * might not negotiate, so it cannot count. Pure apart from WebCrypto, so the
 * tests drive it directly; the caller acts on the verdict (pin, proceed, or
 * stop).
 */
export async function judgePeerAuth(args: {
  asked: { nonce: string; offerFingerprint: string } | null
  sessionId: string
  agentId: string
  userId: string
  answerFingerprint: string | null
  answerPeerAuth: unknown
  pinned: string | null
}): Promise<PeerAuthVerdict> {
  if (!args.asked) return { kind: 'not-asked' }
  const binding = answerBinding(args.answerPeerAuth)
  if (!binding) return { kind: 'unsigned', pinned: args.pinned }
  const transcript =
    args.answerFingerprint === null
      ? null
      : peerAuthTranscript(
          'answer',
          args.sessionId,
          args.agentId,
          args.userId,
          args.asked.offerFingerprint,
          args.answerFingerprint,
          args.asked.nonce,
        )
  if (!transcript || !(await verifyPeerAuth(binding.key, transcript, binding.sig))) {
    return { kind: 'bad-signature', key: binding.key }
  }
  if (args.pinned === null) return { kind: 'first-use', key: binding.key }
  if (args.pinned === binding.key) return { kind: 'pinned', key: binding.key }
  return { kind: 'key-changed', key: binding.key, pinned: args.pinned }
}

/** A verdict with whose pin it concerns and the fingerprints a person compares. */
export interface PeerAuthJudgement {
  verdict: PeerAuthVerdict
  userId: string
  agentId: string
  /** The key the answer was signed with, as the device list shows it. */
  fingerprint: string | null
  /** The key this browser had pinned for the device, if any. */
  pinnedFingerprint: string | null
}

/**
 * What the session toolbar says about the device's key, or `null` for
 * nothing: a session that did not ask, or one already refused (the error view
 * says that).
 */
export function peerAuthBadge(
  judged: PeerAuthJudgement | null,
): { label: string; color: string; icon: string; title: string } | null {
  if (!judged) return null
  const fp = judged.fingerprint ? ` (${judged.fingerprint})` : ''
  switch (judged.verdict.kind) {
    case 'first-use':
      return {
        label: 'Verified',
        color: 'success',
        icon: 'mdi-shield-check-outline',
        title:
          `This device proved its identity key${fp}. This browser had not met it before ` +
          'and now remembers it: a different key next time stops the session.',
      }
    case 'pinned':
      return {
        label: 'Verified',
        color: 'success',
        icon: 'mdi-shield-check',
        title: `This device proved the identity key this browser knows for it${fp}.`,
      }
    case 'unsigned':
      return {
        label: 'Unverified',
        color: 'warning',
        icon: 'mdi-shield-alert-outline',
        title: judged.verdict.pinned
          ? 'This device has proved its identity key to this browser before, but this answer was ' +
            'not signed. The session runs; if this keeps happening, check the device.'
          : 'The device did not sign its answer, so nothing vouches that this session reaches it. ' +
            'The session runs.',
      }
    default:
      return null
  }
}

/**
 * What the page does with a verdict: pin a first key, and say whether the
 * answer may be applied. Only a different key or a bad signature refuses;
 * an unsigned answer proceeds, and the toolbar says so.
 */
export function applyPeerAuthVerdict(
  verdict: PeerAuthVerdict,
  pins: PeerAuthPins,
  userId: string,
  agentId: string,
): 'proceed' | 'refuse' {
  switch (verdict.kind) {
    case 'first-use':
      pins.set(userId, agentId, verdict.key)
      return 'proceed'
    case 'key-changed':
    case 'bad-signature':
      return 'refuse'
    case 'not-asked':
    case 'pinned':
    case 'unsigned':
      return 'proceed'
    default: {
      // A new verdict must be decided here, not fall through to "proceed".
      const undecided: never = verdict
      return undecided
    }
  }
}

/**
 * The person trusts the key a `key-changed` refusal named: pin it for that
 * (user, device). `false`, with nothing pinned, for any other judgement.
 */
export function trustChangedKey(judged: PeerAuthJudgement | null, pins: PeerAuthPins): boolean {
  if (judged?.verdict.kind !== 'key-changed') return false
  pins.set(judged.userId, judged.agentId, judged.verdict.key)
  return true
}

// ─── FR-100 P2b — the browser signs its offer ──────────────────────────────

/**
 * Where this browser keeps its own key pairs, one per user. `add` never
 * replaces: when two tabs make a key at once, the first one kept wins and the
 * other reads it back, so the browser still has ONE key.
 */
export interface ControllerKeyBackend {
  read(userId: string): Promise<CryptoKeyPair | undefined>
  add(userId: string, pair: CryptoKeyPair): Promise<void>
}

function isKeyPair(v: unknown): v is CryptoKeyPair {
  return !!v && typeof v === 'object' && 'privateKey' in v && 'publicKey' in v
}

/**
 * This user's key pair in this browser: read, or made and kept. The private
 * half is made NON-extractable: the page can sign with it while it runs, and
 * nothing can read it out afterwards. `null` when the browser cannot keep a
 * key: one made per page would reach the device as a new browser on every
 * visit, and push out the keys it should remember.
 */
export async function controllerKeyFor(
  userId: string,
  backend: ControllerKeyBackend | null,
): Promise<CryptoKeyPair | null> {
  if (!backend) return null
  try {
    const existing = await backend.read(userId)
    if (isKeyPair(existing)) return existing
    const made = (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    try {
      await backend.add(userId, made)
    } catch {
      // Another tab kept one first: the read below finds it.
    }
    const kept = await backend.read(userId)
    return isKeyPair(kept) ? kept : null
  } catch {
    return null
  }
}

/**
 * The keys in this origin's IndexedDB (`meshharbor-peer-auth` / `controller-keys`,
 * keyed by user id), or `null` where there is none: a CryptoKey is stored as
 * itself, non-extractable as it was made.
 */
export function indexedDbKeyBackend(idb?: IDBFactory): ControllerKeyBackend | null {
  let factory: IDBFactory | undefined = idb
  if (!factory) {
    try {
      factory = globalThis.indexedDB ?? undefined
    } catch {
      factory = undefined
    }
  }
  if (!factory) return null
  const db = factory
  const STORE = 'controller-keys'
  const open = () =>
    new Promise<IDBDatabase>((resolve, reject) => {
      const req = db.open('meshharbor-peer-auth', 1)
      req.onupgradeneeded = () => req.result.createObjectStore(STORE)
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
      req.onblocked = () => reject(new Error('the key store is blocked by another tab'))
    })
  const run = <T>(mode: IDBTransactionMode, ask: (s: IDBObjectStore) => IDBRequest<T>) =>
    open().then(
      (conn) =>
        new Promise<T>((resolve, reject) => {
          const tx = conn.transaction(STORE, mode)
          const req = ask(tx.objectStore(STORE))
          tx.oncomplete = () => {
            conn.close()
            resolve(req.result)
          }
          tx.onerror = () => {
            conn.close()
            reject(tx.error ?? req.error)
          }
          tx.onabort = () => {
            conn.close()
            reject(tx.error ?? new Error('the key store transaction was aborted'))
          }
        }),
    )
  return {
    read: (userId) => run('readonly', (s) => s.get(userId)) as Promise<CryptoKeyPair | undefined>,
    add: (userId, pair) => run('readwrite', (s) => s.add(pair, userId)).then(() => undefined),
  }
}

/** `pair`'s public half in the device key's shape: standard base64 of the 65-byte point. */
export async function controllerPublicKey(pair: CryptoKeyPair): Promise<string> {
  const raw = new Uint8Array(await subtle().exportKey('raw', pair.publicKey))
  let bin = ''
  for (const b of raw) bin += String.fromCharCode(b)
  return btoa(bin)
}

/**
 * The offer's `peer_auth`: the nonce, and, with a key at hand, the key and its
 * signature over the transcript with role `offer` and an EMPTY answer
 * fingerprint (none exists yet). Without a key, or when signing fails, the
 * nonce alone, which the device reads as `absent`: the offer still asks the
 * device to sign its answer either way.
 */
export async function offerAsk(args: {
  nonce: string
  sessionId: string
  agentId: string
  userId: string
  offerFingerprint: string
  pair: CryptoKeyPair | null
}): Promise<{ nonce: string; key?: string; sig?: string }> {
  const ask = { nonce: args.nonce }
  if (!args.pair) return ask
  const transcript = peerAuthTranscript(
    'offer',
    args.sessionId,
    args.agentId,
    args.userId,
    args.offerFingerprint,
    '',
    args.nonce,
  )
  if (!transcript) return ask
  try {
    const sig = new Uint8Array(
      await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, args.pair.privateKey, transcript),
    )
    return { nonce: args.nonce, key: await controllerPublicKey(args.pair), sig: toBase64Url(sig) }
  } catch {
    return ask
  }
}

/** `p`, or `null` once `ms` have passed: a key store that hangs must not hold an offer back. */
export function withinMs<T>(p: Promise<T | null>, ms: number): Promise<T | null> {
  return Promise.race([p, new Promise<null>((resolve) => setTimeout(() => resolve(null), ms))])
}

// ─── X14 — download-only child WebRTC offer proof ──────────────────────────

export const FILE_CHILD_OFFER_LABEL = 'meshharbor-file-child-offer-v1'

export interface FileChildOfferProof {
  nonce: string
  key: string
  sig: string
}

function isCanonicalOidHex(id: string): boolean {
  return /^[0-9a-f]{24}$/.test(id)
}

function isValidTransferId(transferId: string): boolean {
  if (!transferId) return false
  const bytes = new TextEncoder().encode(transferId)
  if (bytes.length === 0 || bytes.length > 128) return false
  for (let i = 0; i < transferId.length; i++) {
    const code = transferId.charCodeAt(i)
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return false
  }
  return true
}

function isWellFormedPeerAuthNonce(nonce: string): boolean {
  const bytes = fromBase64Url(nonce)
  if (!bytes || bytes.length < 16 || bytes.length > 32) return false
  return toBase64Url(bytes) === nonce
}

/**
 * Construct the domain-separated byte transcript for a child WebRTC SDP offer
 * (`file_child_offer_transcript` in `crates/remote_control/src/signaling.rs`).
 */
export function fileChildOfferTranscript(args: {
  sessionId: string
  childId: string
  transferId: string
  agentId: string
  controllerUserId: string
  offerSdp: string
  nonce: string
}): Uint8Array<ArrayBuffer> | null {
  if (
    !isCanonicalOidHex(args.sessionId) ||
    !isCanonicalOidHex(args.childId) ||
    !isCanonicalOidHex(args.agentId) ||
    !isCanonicalOidHex(args.controllerUserId) ||
    !isValidTransferId(args.transferId) ||
    !isWellFormedPeerAuthNonce(args.nonce)
  ) {
    return null
  }
  const fingerprint = singleFingerprint(args.offerSdp)
  if (!fingerprint) return null
  return framed(
    FILE_CHILD_OFFER_LABEL,
    args.sessionId,
    args.childId,
    args.transferId,
    'download',
    args.agentId,
    args.controllerUserId,
    fingerprint,
    args.nonce,
  )
}

/**
 * Generate a fresh session-scoped ephemeral P-256 ECDSA key pair for child
 * download WebRTC transports (`rc:file.child.register`).
 */
export async function generateEphemeralFileChildKeyPair(): Promise<{
  pair: CryptoKeyPair
  publicKeyB64: string
}> {
  const pair = (await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const publicKeyB64 = await controllerPublicKey(pair)
  return { pair, publicKeyB64 }
}

/**
 * Sign a `FileChildOfferProof` over `fileChildOfferTranscript` for a child
 * download `RTCPeerConnection` SDP offer.
 */
export async function signFileChildOfferProof(args: {
  pair: CryptoKeyPair
  publicKeyB64?: string
  sessionId: string
  childId: string
  transferId: string
  agentId: string
  controllerUserId: string
  offerSdp: string
  nonce?: string
}): Promise<FileChildOfferProof | null> {
  const nonce = args.nonce ?? newPeerAuthNonce()
  const transcript = fileChildOfferTranscript({
    sessionId: args.sessionId,
    childId: args.childId,
    transferId: args.transferId,
    agentId: args.agentId,
    controllerUserId: args.controllerUserId,
    offerSdp: args.offerSdp,
    nonce,
  })
  if (!transcript) return null
  try {
    const sig = new Uint8Array(
      await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, args.pair.privateKey, transcript),
    )
    const key = args.publicKeyB64 ?? (await controllerPublicKey(args.pair))
    return { nonce, key, sig: toBase64Url(sig) }
  } catch {
    return null
  }
}

