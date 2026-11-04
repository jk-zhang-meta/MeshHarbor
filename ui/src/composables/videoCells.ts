// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-77 — the viewer's ONE reading of what a device can encode: a list of
// cells (codec × chroma format), each with the backend that produces it and
// whether that backend is hardware. Two consumers share it — the codec picker
// and the admin device chips — so they cannot disagree about a device.
//
// Pure functions, no Vue, so vitest covers every rule without mounting.
import type { AgentCapabilities } from '@/stores/agents'
import type { RcCodecChoice, RcPriority } from '@/composables/useRemoteControl'

export const CELL_CODECS = ['h264', 'hevc', 'av1', 'vp9'] as const
export type CellCodec = (typeof CELL_CODECS)[number]
export const CELL_CHROMAS = ['yuv420', 'yuv444'] as const
export type CellChroma = (typeof CELL_CHROMAS)[number]

/** One encoder (codec × backend) and the chroma formats it opened in. */
export interface Cell {
  codec: CellCodec
  /** Wire backend name; `''` when a legacy row implied the codec through a
   *  transport only, so the backend is genuinely unknown. */
  backend: string
  chroma: CellChroma[]
  hw: boolean
}

const isCodec = (s: string): s is CellCodec => (CELL_CODECS as readonly string[]).includes(s)
const isChroma = (s: string): s is CellChroma => (CELL_CHROMAS as readonly string[]).includes(s)

/**
 * The cells of a device. Reads `video_cells` when the agent sent them
 * (FR-77 P1+); otherwise derives them from the legacy fields exactly the way
 * the picker and the auto-rank read those fields before FR-77, so a
 * pre-FR-77 agent keeps every entry it has today.
 *
 * Unknown codecs / chroma formats from a NEWER agent are skipped, never an
 * error — the additive-list rule. A caps object with neither is a device
 * that advertised nothing (no cells).
 */
export function cellsFromCaps(caps: AgentCapabilities | null | undefined): Cell[] {
  if (!caps) return []
  const fresh = caps.video_cells
  if (Array.isArray(fresh) && fresh.length > 0) {
    const out: Cell[] = []
    for (const c of fresh) {
      if (!c || typeof c.codec !== 'string' || !isCodec(c.codec)) continue
      const chroma = (Array.isArray(c.chroma) ? c.chroma : []).filter(isChroma)
      if (chroma.length === 0) continue
      out.push({ codec: c.codec, backend: typeof c.backend === 'string' ? c.backend : '', chroma, hw: c.hw === true })
    }
    return out
  }
  return legacyCells(caps)
}

/** The pre-FR-77 fields, read as the rc.199 picker and the rc.190 auto-rank
 *  read them: `ffmpeg-<name>` entries are hardware, `hevc_chroma` says what
 *  the HEVC entry can emit, libvpx does both VP9 profiles, and a transport
 *  with no encoder label (rows saved before either existed) still names a
 *  codec. */
export function legacyCells(caps: AgentCapabilities): Cell[] {
  const out: Cell[] = []
  const hevcChroma = (caps.hevc_chroma ?? []).filter(isChroma)
  for (const enc of caps.hw_encoders ?? []) {
    if (enc === 'openh264-sw') {
      out.push({ codec: 'h264', backend: 'openh264', chroma: ['yuv420'], hw: false })
    } else if (enc === 'mf-h264-hw') {
      out.push({ codec: 'h264', backend: 'mf', chroma: ['yuv420'], hw: true })
    } else if (enc === 'mf-h265-hw') {
      out.push({ codec: 'hevc', backend: 'mf', chroma: ['yuv420'], hw: true })
    } else if (enc === 'mf-av1-hw') {
      out.push({ codec: 'av1', backend: 'mf', chroma: ['yuv420'], hw: true })
    } else if (enc === 'libvpx-vp9-444-sw') {
      out.push({ codec: 'vp9', backend: 'libvpx', chroma: ['yuv420', 'yuv444'], hw: false })
    } else if (enc.startsWith('ffmpeg-')) {
      const name = enc.slice('ffmpeg-'.length)
      const idx = name.indexOf('_')
      if (idx <= 0) continue
      const codec = name.slice(0, idx)
      const backend = name.slice(idx + 1)
      if (!isCodec(codec) || !backend) continue
      const chroma: CellChroma[] =
        codec === 'hevc' && hevcChroma.length > 0
          ? [...new Set<CellChroma>(['yuv420', ...hevcChroma])]
          : ['yuv420']
      out.push({ codec, backend, chroma, hw: true })
    }
  }
  const byTransport: [string, CellCodec][] = [
    ['data-channel-av1', 'av1'],
    ['data-channel-hevc', 'hevc'],
    ['data-channel-h264', 'h264'],
    ['data-channel-vp9-444', 'vp9'],
  ]
  for (const [t, codec] of byTransport) {
    if ((caps.transports ?? []).includes(t) && !out.some((c) => c.codec === codec)) {
      out.push({
        codec,
        backend: '',
        chroma: codec === 'vp9' ? ['yuv420', 'yuv444'] : ['yuv420'],
        // The DC transports were hardware-only by construction, except VP9,
        // whose transport is the libvpx software pump.
        hw: codec !== 'vp9',
      })
    }
  }
  return out
}

/** The codec a data-channel transport carries (`null` for the RTP track /
 *  auto). The `-444` in the VP9 transport's name is historical: it carries
 *  both chroma formats. */
export function cellCodecOfTransport(transport: string | null | undefined): CellCodec | null {
  switch (transport) {
    case 'data-channel-av1':
      return 'av1'
    case 'data-channel-hevc':
      return 'hevc'
    case 'data-channel-h264':
      return 'h264'
    case 'data-channel-vp9-444':
      return 'vp9'
    default:
      return null
  }
}

/** Can the device produce `codec` in `chroma` on any backend, and is any
 *  such backend hardware? */
export function agentCan(cells: Cell[], codec: CellCodec, chroma: CellChroma): { ok: boolean; hw: boolean } {
  const hits = cells.filter((c) => c.codec === codec && c.chroma.includes(chroma))
  return { ok: hits.length > 0, hw: hits.some((c) => c.hw) }
}

// ── The picker's two axes ──────────────────────────────────────────────────

export const PICKER_CODECS = ['auto', 'av1', 'hevc', 'vp9', 'h264'] as const
export type PickerCodec = (typeof PICKER_CODECS)[number]
export const PICKER_CHROMAS = ['auto', 'yuv420', 'yuv444'] as const
export type PickerChroma = (typeof PICKER_CHROMAS)[number]

/** Which cells the SESSION pump can actually run today, independent of the
 *  device and the browser. H.264 4:4:4 runs since P3b (NVENC High 4:4:4 encode, software
 *  decode in the browser); AV1
 *  4:4:4 has no hardware encoder anywhere (`av1_nvenc` hard-errors on it). */
export const SESSION_SUPPORTS_444: Record<CellCodec, boolean> = {
  hevc: true,
  vp9: true,
  h264: true,
  av1: false,
}

/** Map the two dropdowns onto the stored choice (the persisted, per-agent
 *  value the connect path already understands). Total: every pair maps. */
export function choiceFromPicker(codec: PickerCodec, chroma: PickerChroma): RcCodecChoice {
  switch (codec) {
    case 'auto':
      return chroma === 'yuv444' ? 'auto-444' : chroma === 'yuv420' ? 'auto-420' : 'auto'
    case 'av1':
      return 'av1'
    case 'hevc':
      return chroma === 'yuv444' ? 'hevc-444' : 'hevc'
    case 'vp9':
      return chroma === 'yuv444' ? 'vp9-444' : chroma === 'yuv420' ? 'vp9-420' : 'vp9'
    case 'h264':
    default:
      return chroma === 'yuv444' ? 'h264-444' : 'h264'
  }
}

/** Reverse of `choiceFromPicker`: what the two dropdowns show for a stored
 *  choice. `hevc` / `av1` / `h264` read as chroma "auto" (they never carried
 *  one); `vp9-420` / `vp9-444` keep their explicit chroma. */
export function pickerFromChoice(choice: RcCodecChoice): { codec: PickerCodec; chroma: PickerChroma } {
  switch (choice) {
    case 'av1':
      return { codec: 'av1', chroma: 'auto' }
    case 'hevc':
      return { codec: 'hevc', chroma: 'auto' }
    case 'hevc-444':
      return { codec: 'hevc', chroma: 'yuv444' }
    case 'vp9':
      return { codec: 'vp9', chroma: 'auto' }
    case 'vp9-444':
      return { codec: 'vp9', chroma: 'yuv444' }
    case 'vp9-420':
      return { codec: 'vp9', chroma: 'yuv420' }
    case 'h264':
      return { codec: 'h264', chroma: 'auto' }
    case 'h264-444':
      return { codec: 'h264', chroma: 'yuv444' }
    case 'auto-444':
      return { codec: 'auto', chroma: 'yuv444' }
    case 'auto-420':
      return { codec: 'auto', chroma: 'yuv420' }
    case 'auto':
    default:
      return { codec: 'auto', chroma: 'auto' }
  }
}

/** Resolve an "auto" chroma at connect time: the priority dial decides
 *  (sharper ⇒ 4:4:4 when the pair can do it, else 4:2:0). Explicit chroma
 *  overrides the dial; the dial only ever fills an "auto". */
export function resolveChroma(chroma: PickerChroma, priority: RcPriority, pairCan444: boolean): CellChroma {
  if (chroma === 'yuv444') return 'yuv444'
  if (chroma === 'yuv420') return 'yuv420'
  return priority === 'sharper' && pairCan444 ? 'yuv444' : 'yuv420'
}

// ── Validity: the matrix the two dropdowns grey against ───────────────────

export interface BrowserDecode {
  /** WebCodecs decodes AV1 (dav1d is universal in Chromium). */
  av1: boolean
  /** HEVC decodes AND is hardware-smooth — the double gate the HEVC pick has
   *  always needed (no software HEVC exists in Chrome). */
  hevc: boolean
  /** WebCodecs accepts the HEVC RExt (4:4:4) codec string. Chromium keeps one
   *  RExt profile for every chroma form, so this cannot distinguish 4:4:4
   *  from 4:2:2 — only a real-bytes trial proves it, and a failed trial is
   *  remembered (see `failed`). */
  hevcRext: boolean
  /** FR-77 P3b — VideoDecoder accepts an avc1 High 4:4:4 string (software decode). */
  h264High444?: boolean
  /** WebCodecs accepts VP9 profile 1 (4:4:4); implies profile 0 too. */
  vp9: boolean
}

export interface AvailabilityInputs {
  cells: Cell[]
  /** False until the device record has arrived: AV1 / HEVC / VP9 4:2:0 are
   *  then OPTIMISTIC (the agent falls back if it cannot honour the pick —
   *  the rc.190 contract), while every 4:4:4 cell demands positive proof
   *  from both ends, because a chroma mismatch is a black screen. */
  capsLoaded: boolean
  browser: BrowserDecode
  /** `${codec}:${chroma}` keys of cells whose decoder failed on real bytes
   *  for THIS device in this browser (page-scoped and remembered). */
  failed: ReadonlySet<string>
}

export interface CellVerdict {
  ok: boolean
  /** i18n key under `remote.codec.reason.*` explaining the verdict. */
  reason: string
  /** Hardware on the device side (undefined when the device is unknown). */
  hw?: boolean
}

export type Availability = Record<CellCodec, Record<CellChroma, CellVerdict>>

export const cellKey = (codec: CellCodec, chroma: CellChroma): string => `${codec}:${chroma}`

/** The whole matrix at once, one verdict per cell, so the codec dropdown can
 *  grey an entry against the chosen chroma and the chroma dropdown against
 *  the chosen codec, both from the same truth. */
export function cellAvailability(i: AvailabilityInputs): Availability {
  const verdict = (codec: CellCodec, chroma: CellChroma): CellVerdict => {
    const agent = agentCan(i.cells, codec, chroma)
    const hw = i.capsLoaded ? agent.hw : undefined
    if (i.failed.has(cellKey(codec, chroma))) {
      return { ok: false, reason: 'failedBefore', hw }
    }
    if (chroma === 'yuv444' && !SESSION_SUPPORTS_444[codec]) {
      return { ok: false, reason: 'av1NoHw444', hw }
    }
    switch (codec) {
      case 'av1': {
        if (!i.browser.av1) return { ok: false, reason: 'browserNoAv1', hw }
        if (i.capsLoaded && !agent.ok) return { ok: false, reason: 'agentNoAv1', hw }
        return { ok: true, reason: 'av1', hw }
      }
      case 'hevc': {
        if (!i.browser.hevc) return { ok: false, reason: 'browserNoHevc', hw }
        if (chroma === 'yuv444') {
          if (!i.browser.hevcRext) return { ok: false, reason: 'browserNoHevcRext', hw }
          if (!agent.ok) return { ok: false, reason: 'agentNoHevc444', hw }
          return { ok: true, reason: 'hevc444', hw }
        }
        if (i.capsLoaded && !agent.ok) return { ok: false, reason: 'agentNoHevc', hw }
        return { ok: true, reason: 'hevc', hw }
      }
      case 'vp9': {
        if (!i.browser.vp9) return { ok: false, reason: 'browserNoVp9', hw }
        if (i.capsLoaded && !agent.ok) return { ok: false, reason: 'agentNoVp9', hw }
        return { ok: true, reason: chroma === 'yuv444' ? (agent.hw ? 'vp9444hw' : 'vp9444') : 'vp9420', hw }
      }
      case 'h264':
      default: {
        if (chroma === 'yuv444') {
          // FR-77 P3b — High 4:4:4 Predictive: hardware encode (NVENC) on
          // the agent, software decode here; both ends must say yes.
          if (!i.browser.h264High444) return { ok: false, reason: 'browserNoH264High444', hw }
          if (!agent.ok) return { ok: false, reason: 'agentNoH264_444', hw }
          return { ok: true, reason: 'h264444', hw }
        }
        return { ok: true, reason: 'h264', hw }
      }
        return { ok: true, reason: 'h264', hw }
    }
  }
  const out = {} as Availability
  for (const codec of CELL_CODECS) {
    out[codec] = { yuv420: verdict(codec, 'yuv420'), yuv444: verdict(codec, 'yuv444') }
  }
  return out
}

/** Is a codec entry selectable given the chroma dropdown's value? */
export function codecSelectable(a: Availability, codec: PickerCodec, chroma: PickerChroma): CellVerdict {
  if (codec === 'auto') return { ok: true, reason: 'auto' }
  if (chroma === 'auto') {
    // Any chroma will do; report the best-looking cell.
    const c420 = a[codec].yuv420
    if (c420.ok) return c420
    const c444 = a[codec].yuv444
    if (c444.ok) return c444
    // Neither opens: the 4:2:0 reason is the one that explains the codec itself.
    return c420
  }
  return a[codec][chroma]
}

/** Is a chroma entry selectable given the codec dropdown's value? */
export function chromaSelectable(a: Availability, codec: PickerCodec, chroma: PickerChroma): CellVerdict {
  if (chroma === 'auto') return { ok: true, reason: 'autoChroma' }
  if (codec === 'auto') {
    const any = CELL_CODECS.map((c) => a[c][chroma]).find((v) => v.ok)
    if (!any) return { ok: false, reason: chroma === 'yuv444' ? 'no444Anywhere' : 'no420Anywhere' }
    // Under codec Auto the 4:2:0 entry describes the FORMAT, not whichever codec happened to pass first.
    return chroma === 'yuv420' ? { ok: true, reason: 'chroma420' } : any
  }
  return a[codec][chroma]
}

// ── Remembered decode failures (per device × cell, per browser build) ─────

export const CELL_FAILURE_PREFIX = 'meshharbor-rc-cell-failed.v1:'

interface StoredFailures {
  [key: string]: { ua: string; at: number }
}

function readFailures(agentId: string): StoredFailures {
  try {
    const raw = globalThis.localStorage?.getItem(CELL_FAILURE_PREFIX + agentId)
    if (!raw) return {}
    const parsed: unknown = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? (parsed as StoredFailures) : {}
  } catch {
    return {}
  }
}

/** Record that `codec:chroma` failed to decode real bytes from `agentId` in
 *  this browser. Keyed with the user-agent string so a browser (or, on
 *  Chromium, a GPU driver bump that changes it) gets a fresh trial. */
export function rememberCellFailure(agentId: string, codec: CellCodec, chroma: CellChroma, ua: string): void {
  try {
    const all = readFailures(agentId)
    all[cellKey(codec, chroma)] = { ua, at: Date.now() }
    globalThis.localStorage?.setItem(CELL_FAILURE_PREFIX + agentId, JSON.stringify(all))
  } catch {
    /* best-effort */
  }
}

/** The cells remembered as failed for `agentId` under THIS `ua`; entries
 *  recorded under another user-agent string are ignored (the trial is worth
 *  repeating after an upgrade) and dropped. */
export function rememberedCellFailures(agentId: string, ua: string): Set<string> {
  const all = readFailures(agentId)
  const out = new Set<string>()
  for (const [key, v] of Object.entries(all)) {
    if (v && v.ua === ua) out.add(key)
  }
  return out
}

export function forgetCellFailures(agentId: string): void {
  try {
    globalThis.localStorage?.removeItem(CELL_FAILURE_PREFIX + agentId)
  } catch {
    /* best-effort */
  }
}
