// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-92 — keep busy, the viewer's half: the `rc:keep-busy.*` wire on the
 * session's `control` DataChannel, the words, and the pattern previews.
 *
 * The DEVICE decides and owns the state. A viewer asks (`rc:keep-busy.set`)
 * and renders whatever `rc:keep-busy.state` the agent broadcasts to every
 * viewer. A viewer never re-asserts keep-busy on connect (unlike
 * display-match): a reconnecting tab must not undo the host's Stop or
 * another controller's choice.
 *
 * Pure on purpose — no Vue, no channel — so all of it is unit-tested.
 */

export type KeepBusyPattern =
  | 'circle'
  | 'triangle'
  | 'square'
  | 'star'
  | 'figure8'
  | 'heart'
  | 'spirograph'
  | 'lissajous'
  | 'rose'
  | 'wave'
  | 'wander'
  | 'subtle'
  | 'shuffle'
export type KeepBusySize = 's' | 'm' | 'l'
export type KeepBusySpeed = 'slow' | 'normal' | 'fast'
export type KeepBusyPhase =
  | 'off'
  | 'calibrating'
  | 'running'
  | 'paused'
  | 'locked'
  | 'unavailable'

/** The agent's `rc:keep-busy.state`, parsed. */
export interface KeepBusyState {
  rev: number
  /** Can it be turned on here at all (not denied, not blocked)? */
  available: boolean
  on: boolean
  phase: KeepBusyPhase
  /** A closed set of codes (`user_active`, `locked`, `org_denied`, …). */
  reason: string | null
  /** The agent's own sentence for `reason` — shown verbatim. */
  sentence: string | null
  pausedBy: 'local' | 'remote' | null
  /** Remaining pause when the agent sent it (see `receivedAt`). */
  resumesInMs: number | null
  /** Local clock (ms) at parse time — the countdown runs from here. */
  receivedAt: number
  pattern: KeepBusyPattern
  size: KeepBusySize
  speed: KeepBusySpeed
  resumeAfterS: number
  autoOffAtMs: number | null
  setBy: string | null
  setAtMs: number | null
  detector: string
  warn: string[]
  /** Why THIS viewer's last request was not applied, when it was not. */
  refused: string | null
}

export const KEEP_BUSY_PATTERNS: { id: KeepBusyPattern; label: string }[] = [
  { id: 'circle', label: 'Circle' },
  { id: 'triangle', label: 'Triangle' },
  { id: 'square', label: 'Square' },
  { id: 'star', label: 'Star' },
  { id: 'figure8', label: 'Figure 8' },
  { id: 'heart', label: 'Heart' },
  { id: 'spirograph', label: 'Spirograph' },
  { id: 'lissajous', label: 'Lissajous' },
  { id: 'rose', label: 'Rose' },
  { id: 'wave', label: 'Wave' },
  { id: 'wander', label: 'Wander' },
  { id: 'subtle', label: 'Subtle' },
  { id: 'shuffle', label: 'Shuffle' },
]

/** Resume delays offered, in seconds. */
export const KEEP_BUSY_RESUME_CHOICES = [10, 30, 60, 120, 300] as const
/** Auto-off choices, in minutes; 0 = never. */
export const KEEP_BUSY_AUTO_OFF_CHOICES = [0, 30, 60, 120, 240, 480] as const

const PATTERN_IDS = new Set<string>(KEEP_BUSY_PATTERNS.map((p) => p.id))

/** Is `v` a pattern this viewer knows, by exact id? (FR-92 P8: the org's
 *  default comes from the server as a word; an unknown one means circle.) */
export function isKeepBusyPattern(v: unknown): v is KeepBusyPattern {
  return typeof v === 'string' && PATTERN_IDS.has(v)
}
const PHASES = new Set<string>(['off', 'calibrating', 'running', 'paused', 'locked', 'unavailable'])

function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/**
 * Parse `rc:keep-busy.state`. `null` when it is not one. Unknown values
 * degrade to safe defaults rather than throwing: a newer agent may send a
 * pattern this viewer cannot draw, and the state must still show.
 */
export function parseKeepBusyState(
  obj: Record<string, unknown>,
  now: number = Date.now(),
): KeepBusyState | null {
  if (obj.t !== 'rc:keep-busy.state') return null
  if (typeof obj.on !== 'boolean' || typeof obj.available !== 'boolean') return null
  const phase = str(obj.phase)
  const pattern = str(obj.pattern)
  const size = str(obj.size)
  const speed = str(obj.speed)
  const pausedBy = str(obj.paused_by)
  return {
    rev: num(obj.rev) ?? 0,
    available: obj.available,
    on: obj.on,
    phase: phase && PHASES.has(phase) ? (phase as KeepBusyPhase) : 'unavailable',
    reason: str(obj.reason),
    sentence: str(obj.sentence),
    pausedBy: pausedBy === 'local' || pausedBy === 'remote' ? pausedBy : null,
    resumesInMs: num(obj.resumes_in_ms),
    receivedAt: now,
    pattern: pattern && PATTERN_IDS.has(pattern) ? (pattern as KeepBusyPattern) : 'circle',
    size: size === 's' || size === 'm' || size === 'l' ? size : 'm',
    speed: speed === 'slow' || speed === 'normal' || speed === 'fast' ? speed : 'normal',
    resumeAfterS: num(obj.resume_after_s) ?? 30,
    autoOffAtMs: num(obj.auto_off_at_ms),
    setBy: str(obj.set_by),
    setAtMs: num(obj.set_at_ms),
    detector: str(obj.detector) ?? '',
    warn: Array.isArray(obj.warn) ? obj.warn.filter((w): w is string => typeof w === 'string') : [],
    refused: str(obj.refused),
  }
}

export interface KeepBusyRequest {
  on: boolean
  pattern?: KeepBusyPattern
  size?: KeepBusySize
  speed?: KeepBusySpeed
  resumeAfterS?: number
  /** Minutes until it turns itself off; 0 or null = never. */
  autoOffMin?: number | null
}

/** The `rc:keep-busy.set` message for a request. An "off" carries nothing
 *  else — it must work whatever the rest of the form says. */
export function keepBusySetMessage(req: KeepBusyRequest): Record<string, unknown> {
  if (!req.on) return { t: 'rc:keep-busy.set', on: false }
  return {
    t: 'rc:keep-busy.set',
    on: true,
    pattern: req.pattern ?? 'circle',
    size: req.size ?? 'm',
    speed: req.speed ?? 'normal',
    resume_after_s: req.resumeAfterS ?? 30,
    auto_off_min: req.autoOffMin ? req.autoOffMin : null,
  }
}

export function patternLabel(p: KeepBusyPattern): string {
  return KEEP_BUSY_PATTERNS.find((x) => x.id === p)?.label ?? p
}

/** FR-92 P5b — the device list's tooltip for a device's keep-busy brief (the
 *  heartbeat's claim). Empty unless it is on: off and unknown show nothing. */
export function keepBusyBriefTitle(
  b: { on: boolean; phase: string; reason?: string; pattern?: string; set_by?: string } | undefined,
): string {
  if (!b?.on) return ''
  // A string, not a `KeepBusyPattern`: a newer agent may draw a pattern this
  // dashboard has never heard of, and it is printed as the agent named it.
  const label = b.pattern ? (KEEP_BUSY_PATTERNS.find((x) => x.id === b.pattern)?.label ?? b.pattern) : null
  const what = label ? label.toLowerCase() : 'a pattern'
  const who = b.set_by ? `, turned on by ${b.set_by}` : ''
  const why = b.reason ? ` (${b.reason.replace(/_/g, ' ')})` : ''
  return `Keep busy is on: ${what}${who}. Now ${b.phase}${why}, as the device reports it.`
}

/** What the viewer says about a refusal of its own request. */
export function keepBusyRefusalText(code: string): string {
  switch (code) {
    case 'no_input_permission':
      return 'This session is view-only, so it cannot change keep busy.'
    case 'not_floor_holder':
      return 'Another viewer has control. Ask for control to change keep busy.'
    case 'org_denied':
      return 'Your organization does not allow keep busy.'
    case 'unsupported':
      return 'Keep busy is not available on this computer.'
    case 'bad_request':
      return 'The device did not understand the request. Its agent may need an update.'
    default:
      return 'The device did not apply the change.'
  }
}

/** Seconds left of a pause, counted down locally from the agent's figure. */
export function keepBusyResumesInS(s: KeepBusyState, now: number = Date.now()): number | null {
  if (s.resumesInMs == null) return null
  return Math.max(0, Math.ceil((s.resumesInMs - (now - s.receivedAt)) / 1000))
}

/** One line for the menu and the toolbar chip's tooltip. */
export function keepBusyStatusLine(s: KeepBusyState, now: number = Date.now()): string {
  if (!s.available && s.sentence) return s.sentence
  if (!s.on) {
    // "Turned off at this computer" is worth saying; a plain off is not.
    if (s.sentence && s.reason && s.reason !== 'stopped_by_controller') return s.sentence
    return 'Off.'
  }
  switch (s.phase) {
    case 'running':
      return `Running: ${patternLabel(s.pattern).toLowerCase()}${s.setBy ? `, turned on by ${s.setBy}` : ''}.`
    case 'calibrating':
      return 'Starting…'
    case 'paused': {
      const base = s.sentence ?? 'Paused.'
      if (s.reason !== 'user_active' && s.reason !== 'cursor_contended') return base
      const left = keepBusyResumesInS(s, now)
      if (left == null) return base
      return left > 0 ? `${base} Resumes in ${left} s if nothing else happens.` : `${base} Resumes once they stop.`
    }
    case 'locked':
    case 'unavailable':
      return s.sentence ?? 'Paused.'
    default:
      return s.sentence ?? ''
  }
}

// ─── Previews ───────────────────────────────────────────────────────────
// The same curves the agent draws (`agents/meshharbord/src/keep_busy/patterns.rs`),
// sampled into an SVG path. Only the picture is shared, never the motion:
// the agent remains the one that moves anything.

type Pt = [number, number]
const TAU = Math.PI * 2

function sampleCurve(f: (t: number) => Pt, t0: number, t1: number, n = 240): Pt[] {
  const pts: Pt[] = []
  for (let i = 0; i < n; i++) pts.push(f(t0 + ((t1 - t0) * i) / n))
  return pts
}

function regular(n: number, phase: number): Pt[] {
  const out: Pt[] = []
  for (let k = 0; k < n; k++) {
    const a = phase + (TAU * k) / n
    out.push([Math.cos(a), Math.sin(a)])
  }
  return out
}

/** A seeded generator, so the Wander preview is the same picture every time. */
function mix(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let z = s
    z = Math.imul(z ^ (z >>> 15), z | 1)
    z ^= z + Math.imul(z ^ (z >>> 7), z | 61)
    return ((z ^ (z >>> 14)) >>> 0) / 4294967296
  }
}

function catmullRom(p0: Pt, p1: Pt, p2: Pt, p3: Pt, t: number): Pt {
  const t2 = t * t
  const t3 = t2 * t
  const f = (a: number, b: number, c: number, d: number) =>
    0.5 * (2 * b + (-a + c) * t + (2 * a - 5 * b + 4 * c - d) * t2 + (-a + 3 * b - 3 * c + d) * t3)
  return [f(p0[0], p1[0], p2[0], p3[0]), f(p0[1], p1[1], p2[1], p3[1])]
}

/** A closed curve in unit space for `p` (one polyline; Shuffle is three). */
export function patternPoints(p: KeepBusyPattern): Pt[][] {
  switch (p) {
    case 'circle':
      return [sampleCurve((t) => [Math.cos(t), Math.sin(t)], 0, TAU)]
    case 'triangle':
      return [regular(3, -Math.PI / 2)]
    case 'square':
      return [
        [
          [-1, -1],
          [1, -1],
          [1, 1],
          [-1, 1],
        ],
      ]
    case 'star': {
      const v = regular(5, -Math.PI / 2)
      return [[v[0], v[2], v[4], v[1], v[3]]]
    }
    case 'figure8':
      return [sampleCurve((t) => [Math.sin(t), Math.sin(t) * Math.cos(t) * 1.6], 0, TAU)]
    case 'heart':
      return [
        sampleCurve(
          (t) => [
            (16 * Math.sin(t) ** 3) / 17,
            -(13 * Math.cos(t) - 5 * Math.cos(2 * t) - 2 * Math.cos(3 * t) - Math.cos(4 * t)) / 17,
          ],
          0,
          TAU,
        ),
      ]
    case 'spirograph': {
      const [R, r, d] = [5, 3, 5]
      const k = (R - r) / r
      return [
        sampleCurve(
          (t) => [(R - r) * Math.cos(t) + d * Math.cos(k * t), (R - r) * Math.sin(t) - d * Math.sin(k * t)],
          0,
          3 * TAU,
          480,
        ),
      ]
    }
    case 'lissajous':
      return [sampleCurve((t) => [Math.sin(3 * t + Math.PI / 2), Math.sin(2 * t)], 0, TAU)]
    case 'rose':
      return [sampleCurve((t) => [Math.cos(4 * t) * Math.cos(t), Math.cos(4 * t) * Math.sin(t)], 0, TAU, 480)]
    case 'wave': {
      const a = 0.4
      return [
        sampleCurve(
          (t) => {
            if (t < Math.PI) {
              const x = -1 + (2 * t) / Math.PI
              return [x, a * Math.sin(3 * Math.PI * x)]
            }
            const x = 1 - (2 * (t - Math.PI)) / Math.PI
            return [x, -a * Math.sin(3 * Math.PI * x)]
          },
          0,
          TAU,
        ),
      ]
    }
    case 'wander': {
      const rnd = mix(92)
      const w: Pt[] = Array.from({ length: 6 }, () => [rnd() * 2 - 1, rnd() * 2 - 1] as Pt)
      const pts: Pt[] = []
      for (let leg = 0; leg < w.length; leg++) {
        const at = (i: number) => w[(i + w.length) % w.length]
        for (let k = 0; k < 40; k++) {
          pts.push(catmullRom(at(leg - 1), at(leg), at(leg + 1), at(leg + 2), k / 40))
        }
      }
      return [pts]
    }
    case 'subtle':
      // A dot: the motion is a single pixel and invisible by design.
      return [sampleCurve((t) => [0.12 * Math.cos(t), 0.12 * Math.sin(t)], 0, TAU, 24)]
    case 'shuffle':
      return [
        sampleCurve((t) => [0.45 * Math.cos(t) - 0.4, 0.45 * Math.sin(t) - 0.35], 0, TAU, 60),
        regular(3, -Math.PI / 2).map(([x, y]) => [0.45 * x + 0.45, 0.45 * y - 0.3] as Pt),
        [regular(5, -Math.PI / 2)].map((v) => [v[0], v[2], v[4], v[1], v[3]])[0].map(
          ([x, y]) => [0.45 * x, 0.45 * y + 0.45] as Pt,
        ),
      ]
  }
}

/** Normalise a set of polylines together into `[-1, 1]²` (aspect kept). */
function normaliseAll(polys: Pt[][], keepScale: boolean): Pt[][] {
  if (keepScale) return polys
  let [x0, y0, x1, y1] = [Infinity, Infinity, -Infinity, -Infinity]
  for (const poly of polys)
    for (const [x, y] of poly) {
      x0 = Math.min(x0, x)
      y0 = Math.min(y0, y)
      x1 = Math.max(x1, x)
      y1 = Math.max(y1, y)
    }
  const [cx, cy] = [(x0 + x1) / 2, (y0 + y1) / 2]
  const half = Math.max((x1 - x0) / 2, (y1 - y0) / 2, 1e-9)
  return polys.map((poly) => poly.map(([x, y]) => [(x - cx) / half, (y - cy) / half] as Pt))
}

/**
 * The SVG path (`d`) of a pattern's preview, in a `box`×`box` viewBox with
 * `pad` px of margin. Every subpath is closed.
 */
export function patternPreviewPath(p: KeepBusyPattern, box = 48, pad = 6): string {
  // Subtle and Shuffle keep their composed scale (a dot is a dot).
  const polys = normaliseAll(patternPoints(p), p === 'subtle' || p === 'shuffle')
  const span = box - 2 * pad
  const map = ([x, y]: Pt) => [pad + ((x + 1) / 2) * span, pad + ((y + 1) / 2) * span]
  return polys
    .map((poly) =>
      poly
        .map((pt, i) => {
          const [sx, sy] = map(pt)
          return `${i === 0 ? 'M' : 'L'}${sx.toFixed(1)} ${sy.toFixed(1)}`
        })
        .join(' ') + ' Z',
    )
    .join(' ')
}
