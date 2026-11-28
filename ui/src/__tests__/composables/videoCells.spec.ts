// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it } from 'vitest'
import type { AgentCapabilities } from '@/stores/agents'
import {
  CELL_FAILURE_PREFIX,
  cellAvailability,
  cellCodecOfTransport,
  cellsFromCaps,
  choiceFromPicker,
  chromaSelectable,
  codecSelectable,
  forgetCellFailures,
  legacyCells,
  pickerFromChoice,
  rememberCellFailure,
  rememberedCellFailures,
  resolveChroma,
  PICKER_CHROMAS,
  PICKER_CODECS,
} from '@/composables/videoCells'
import { RC_CODEC_CHOICES } from '@/composables/useRemoteControl'

const base: AgentCapabilities = {
  codecs: [],
  hw_encoders: [],
  has_input_permission: true,
  supports_clipboard: true,
  supports_file_transfer: true,
  max_simultaneous_sessions: 2,
} as AgentCapabilities

/** The recorded 0.4.79 hello of the dev box (RTX 5090 Laptop + Radeon 610M),
 *  before `video_cells` existed — the fixture every legacy reading is judged
 *  against. */
const devBox0479: AgentCapabilities = {
  ...base,
  hw_encoders: [
    'openh264-sw',
    'mf-h264-hw',
    'ffmpeg-hevc_nvenc',
    'ffmpeg-av1_nvenc',
    'ffmpeg-h264_nvenc',
    'libvpx-vp9-444-sw',
  ],
  codecs: ['h264', 'h265', 'av1'],
  transports: ['data-channel-hevc', 'data-channel-av1', 'data-channel-h264', 'data-channel-vp9-444'],
  vp9_chroma: 'yuv444',
  hevc_chroma: ['yuv420', 'yuv444'],
}

describe('FR-77 cellsFromCaps — one derivation for the picker and the chips', () => {
  it('reads a legacy hello exactly as the rc.199 picker read it', () => {
    const cells = cellsFromCaps(devBox0479)
    const find = (codec: string, backend: string) => cells.find((c) => c.codec === codec && c.backend === backend)
    expect(find('h264', 'openh264')).toEqual({ codec: 'h264', backend: 'openh264', chroma: ['yuv420'], hw: false })
    expect(find('h264', 'mf')).toEqual({ codec: 'h264', backend: 'mf', chroma: ['yuv420'], hw: true })
    expect(find('hevc', 'nvenc')).toEqual({ codec: 'hevc', backend: 'nvenc', chroma: ['yuv420', 'yuv444'], hw: true })
    expect(find('av1', 'nvenc')).toEqual({ codec: 'av1', backend: 'nvenc', chroma: ['yuv420'], hw: true })
    expect(find('h264', 'nvenc')).toEqual({ codec: 'h264', backend: 'nvenc', chroma: ['yuv420'], hw: true })
    expect(find('vp9', 'libvpx')).toEqual({ codec: 'vp9', backend: 'libvpx', chroma: ['yuv420', 'yuv444'], hw: false })
    // The transports added nothing the labels had not already named.
    expect(cells).toHaveLength(6)
  })

  it('a legacy non-nvenc HEVC host has no 4:4:4 cell', () => {
    const cells = legacyCells({ ...base, hw_encoders: ['ffmpeg-hevc_qsv'], hevc_chroma: ['yuv420'] })
    expect(cells).toEqual([{ codec: 'hevc', backend: 'qsv', chroma: ['yuv420'], hw: true }])
  })

  it('a transport with no encoder label still names its codec (rows saved before labels existed)', () => {
    const cells = legacyCells({ ...base, transports: ['data-channel-av1', 'data-channel-vp9-444'] })
    expect(cells).toEqual([
      { codec: 'av1', backend: '', chroma: ['yuv420'], hw: true },
      { codec: 'vp9', backend: '', chroma: ['yuv420', 'yuv444'], hw: false },
    ])
  })

  it('prefers video_cells when the agent sent them, skipping what this bundle cannot name', () => {
    const cells = cellsFromCaps({
      ...devBox0479,
      video_cells: [
        { codec: 'hevc', backend: 'nvenc', chroma: ['yuv420', 'yuv444'], hw: true },
        { codec: 'hevc', backend: 'qsv', chroma: ['yuv420'], hw: true },
        { codec: 'vvc', backend: 'nvenc', chroma: ['yuv420'], hw: true },
        { codec: 'av1', backend: 'vulkan', chroma: ['yuv420', 'yuv422'], hw: true },
        { codec: 'vp9', backend: 'libvpx', chroma: ['yuv999'], hw: false },
      ],
    })
    expect(cells).toEqual([
      { codec: 'hevc', backend: 'nvenc', chroma: ['yuv420', 'yuv444'], hw: true },
      { codec: 'hevc', backend: 'qsv', chroma: ['yuv420'], hw: true },
      // an unknown backend name is kept (it is only shown), an unknown codec
      // or an entirely unknown chroma list is dropped
      { codec: 'av1', backend: 'vulkan', chroma: ['yuv420'], hw: true },
    ])
  })

  it('an empty video_cells list falls back to the legacy fields (a probe that died)', () => {
    expect(cellsFromCaps({ ...devBox0479, video_cells: [] })).toHaveLength(6)
    expect(cellsFromCaps(undefined)).toEqual([])
    expect(cellsFromCaps(null)).toEqual([])
  })

  it('maps transports to codecs', () => {
    expect(cellCodecOfTransport('data-channel-vp9-444')).toBe('vp9')
    expect(cellCodecOfTransport('data-channel-hevc')).toBe('hevc')
    expect(cellCodecOfTransport('webrtc')).toBeNull()
    expect(cellCodecOfTransport(null)).toBeNull()
  })
})

describe('FR-77 the two-axis picker ↔ the stored choice', () => {
  it('every (codec, chroma) pair maps to a stored choice and back', () => {
    for (const codec of PICKER_CODECS) {
      for (const chroma of PICKER_CHROMAS) {
        const choice = choiceFromPicker(codec, chroma)
        expect(RC_CODEC_CHOICES).toContain(choice)
        const back = pickerFromChoice(choice)
        expect(back.codec).toBe(codec)
        // AV1 (a single chroma) and the auto/420 HEVC and H.264 pairs (FR-77 P3b:
        // H.264 has its 4:4:4 choice now) read back as "auto" chroma.
        const collapses =
          codec === 'av1' || ((codec === 'hevc' || codec === 'h264') && chroma !== 'yuv444')
        expect(back.chroma).toBe(collapses ? 'auto' : chroma)
      }
    }
  })

  it('locks the pairs the connect path already understands', () => {
    expect(choiceFromPicker('hevc', 'yuv444')).toBe('hevc-444')
    expect(choiceFromPicker('vp9', 'yuv444')).toBe('vp9-444')
    expect(choiceFromPicker('vp9', 'yuv420')).toBe('vp9-420')
    expect(choiceFromPicker('vp9', 'auto')).toBe('vp9')
    expect(choiceFromPicker('auto', 'yuv444')).toBe('auto-444')
    expect(choiceFromPicker('auto', 'yuv420')).toBe('auto-420')
    expect(choiceFromPicker('auto', 'auto')).toBe('auto')
    for (const choice of RC_CODEC_CHOICES) {
      // every stored choice reads back onto the two axes
      const { codec, chroma } = pickerFromChoice(choice)
      expect(PICKER_CODECS).toContain(codec)
      expect(PICKER_CHROMAS).toContain(chroma)
    }
  })

  it('resolveChroma: explicit wins, Auto follows the dial only when the pair can', () => {
    expect(resolveChroma('yuv444', 'balanced', false)).toBe('yuv444')
    expect(resolveChroma('yuv420', 'sharper', true)).toBe('yuv420')
    expect(resolveChroma('auto', 'sharper', true)).toBe('yuv444')
    expect(resolveChroma('auto', 'sharper', false)).toBe('yuv420')
    expect(resolveChroma('auto', 'balanced', true)).toBe('yuv420')
    expect(resolveChroma('auto', 'smoother', true)).toBe('yuv420')
  })
})

describe('FR-77 cellAvailability — validity is a matrix', () => {
  const browserAll = { av1: true, hevc: true, hevcRext: true, vp9: true }
  const cells = cellsFromCaps(devBox0479)

  it('the dev box against a Chrome with NVIDIA Rext decode: every real cell open, AV1/H.264 4:4:4 closed', () => {
    const a = cellAvailability({ cells, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(a.av1.yuv420.ok).toBe(true)
    expect(a.av1.yuv444).toMatchObject({ ok: false, reason: 'av1NoHw444' })
    expect(a.hevc.yuv420.ok).toBe(true)
    expect(a.hevc.yuv444).toMatchObject({ ok: true, reason: 'hevc444', hw: true })
    expect(a.vp9.yuv420.ok).toBe(true)
    expect(a.vp9.yuv444).toMatchObject({ ok: true, hw: false })
    expect(a.h264.yuv420.ok).toBe(true)
    expect(a.h264.yuv444).toMatchObject({ ok: false, reason: 'browserNoH264High444' })
  })

  it('4:4:4 demands proof from both ends; 4:2:0 stays optimistic until caps arrive', () => {
    const noRext = cellAvailability({ cells, capsLoaded: true, browser: { ...browserAll, hevcRext: false }, failed: new Set() })
    expect(noRext.hevc.yuv444).toMatchObject({ ok: false, reason: 'browserNoHevcRext' })
    expect(noRext.hevc.yuv420.ok).toBe(true)

    const qsvHost = cellAvailability({
      cells: legacyCells({ ...base, hw_encoders: ['ffmpeg-hevc_qsv'], hevc_chroma: ['yuv420'] }),
      capsLoaded: true,
      browser: browserAll,
      failed: new Set(),
    })
    expect(qsvHost.hevc.yuv444).toMatchObject({ ok: false, reason: 'agentNoHevc444' })
    expect(qsvHost.av1.yuv420).toMatchObject({ ok: false, reason: 'agentNoAv1' })

    const unknownAgent = cellAvailability({ cells: [], capsLoaded: false, browser: browserAll, failed: new Set() })
    expect(unknownAgent.av1.yuv420.ok).toBe(true)
    expect(unknownAgent.hevc.yuv420.ok).toBe(true)
    expect(unknownAgent.hevc.yuv444.ok).toBe(false)
    expect(unknownAgent.vp9.yuv420.ok).toBe(true)
  })

  it('the browser closes what it cannot decode, and H.264 4:2:0 is always reachable', () => {
    const a = cellAvailability({
      cells,
      capsLoaded: true,
      browser: { av1: false, hevc: false, hevcRext: false, vp9: false },
      failed: new Set(),
    })
    expect(a.av1.yuv420).toMatchObject({ ok: false, reason: 'browserNoAv1' })
    expect(a.hevc.yuv420).toMatchObject({ ok: false, reason: 'browserNoHevc' })
    expect(a.vp9.yuv420).toMatchObject({ ok: false, reason: 'browserNoVp9' })
    expect(a.h264.yuv420.ok).toBe(true)
  })

  it('a remembered decode failure closes exactly that cell', () => {
    const a = cellAvailability({ cells, capsLoaded: true, browser: browserAll, failed: new Set(['hevc:yuv444']) })
    expect(a.hevc.yuv444).toMatchObject({ ok: false, reason: 'failedBefore' })
    expect(a.hevc.yuv420.ok).toBe(true)
  })

  it('codecSelectable / chromaSelectable cross the two dropdowns', () => {
    const a = cellAvailability({ cells, capsLoaded: true, browser: { ...browserAll, hevcRext: false }, failed: new Set() })
    expect(codecSelectable(a, 'auto', 'yuv444').ok).toBe(true)
    expect(codecSelectable(a, 'hevc', 'yuv444').ok).toBe(false)
    expect(codecSelectable(a, 'hevc', 'auto').ok).toBe(true)
    expect(codecSelectable(a, 'av1', 'yuv444').ok).toBe(false)
    expect(codecSelectable(a, 'vp9', 'yuv444').ok).toBe(true)
    expect(chromaSelectable(a, 'auto', 'auto').ok).toBe(true)
    expect(chromaSelectable(a, 'auto', 'yuv444').ok).toBe(true) // VP9 can
    expect(chromaSelectable(a, 'av1', 'yuv444').ok).toBe(false)
    expect(chromaSelectable(a, 'hevc', 'yuv444')).toMatchObject({ ok: false, reason: 'browserNoHevcRext' })
    const none = cellAvailability({ cells, capsLoaded: true, browser: { av1: true, hevc: true, hevcRext: false, vp9: false }, failed: new Set() })
    expect(chromaSelectable(none, 'auto', 'yuv444')).toMatchObject({ ok: false, reason: 'no444Anywhere' })
  })
})

describe('FR-77 remembered decode failures', () => {
  const A = 'agent-aaa'
  beforeEach(() => forgetCellFailures(A))

  it('remembers per device × cell under the browser build that failed, and forgets on a new one', () => {
    rememberCellFailure(A, 'hevc', 'yuv444', 'UA/1')
    expect(rememberedCellFailures(A, 'UA/1')).toEqual(new Set(['hevc:yuv444']))
    expect(rememberedCellFailures(A, 'UA/2')).toEqual(new Set())
    expect(rememberedCellFailures('agent-bbb', 'UA/1')).toEqual(new Set())
    rememberCellFailure(A, 'vp9', 'yuv444', 'UA/1')
    expect(rememberedCellFailures(A, 'UA/1')).toEqual(new Set(['hevc:yuv444', 'vp9:yuv444']))
    forgetCellFailures(A)
    expect(globalThis.localStorage?.getItem(CELL_FAILURE_PREFIX + A)).toBeNull()
  })

  it('survives garbage in storage', () => {
    globalThis.localStorage?.setItem(CELL_FAILURE_PREFIX + A, '{not json')
    expect(rememberedCellFailures(A, 'UA/1')).toEqual(new Set())
  })

  it('expires remembered decode failures after 24h so transient GPU faults self-heal', () => {
    const expiredAt = Date.now() - 25 * 60 * 60 * 1000
    const freshAt = Date.now() - 1000
    globalThis.localStorage?.setItem(
      CELL_FAILURE_PREFIX + A,
      JSON.stringify({
        'hevc:yuv444': { ua: 'UA/1', at: expiredAt },
        'vp9:yuv444': { ua: 'UA/1', at: freshAt },
      }),
    )
    expect(rememberedCellFailures(A, 'UA/1')).toEqual(new Set(['vp9:yuv444']))
  })
})

describe('FR-77 picker subtitles read from the live site (2026-09-07)', () => {
  const browserAll = { av1: true, hevc: true, hevcRext: true, vp9: true }
  // CORPLAP-3's 0.4.83 cells: no HEVC cell at all.
  const corplap3 = cellsFromCaps({
    ...base,
    video_cells: [
      { codec: 'h264', backend: 'openh264', chroma: ['yuv420'], hw: false },
      { codec: 'h264', backend: 'mf', chroma: ['yuv420'], hw: false },
      { codec: 'vp9', backend: 'qsv', chroma: ['yuv420'], hw: true },
      { codec: 'av1', backend: 'qsv', chroma: ['yuv420'], hw: true },
      { codec: 'h264', backend: 'qsv', chroma: ['yuv420'], hw: true },
      { codec: 'vp9', backend: 'libvpx', chroma: ['yuv420', 'yuv444'], hw: false },
    ],
  })

  it('a codec greyed on both chroma formats quotes the 4:2:0 reason, not the 4:4:4 one', () => {
    const a = cellAvailability({ cells: corplap3, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(codecSelectable(a, 'hevc', 'auto')).toMatchObject({ ok: false, reason: 'agentNoHevc' })
    // …while a codec that opens only in 4:4:4 (never the case today) would still surface that cell.
    expect(codecSelectable(a, 'vp9', 'auto').ok).toBe(true)
  })

  it('the 4:2:0 entry under codec Auto describes the format, not whichever codec passed first', () => {
    const a = cellAvailability({ cells: corplap3, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(chromaSelectable(a, 'auto', 'yuv420')).toMatchObject({ ok: true, reason: 'chroma420' })
    expect(chromaSelectable(a, 'auto', 'yuv444')).toMatchObject({ ok: true, reason: 'vp9444' })
  })
})

describe('FR-77 P3b — H.264 4:4:4 and hardware VP9 4:4:4 cells', () => {
  const browserAll = { av1: true, hevc: true, hevcRext: true, vp9: true, h264High444: true }
  const nvidiaHost = cellsFromCaps({
    ...base,
    video_cells: [
      { codec: 'h264', backend: 'nvenc', chroma: ['yuv420', 'yuv444'], hw: true },
      { codec: 'hevc', backend: 'nvenc', chroma: ['yuv420', 'yuv444'], hw: true },
      { codec: 'vp9', backend: 'libvpx', chroma: ['yuv420', 'yuv444'], hw: false },
    ],
  })
  const intelHost = cellsFromCaps({
    ...base,
    video_cells: [
      { codec: 'h264', backend: 'qsv', chroma: ['yuv420'], hw: true },
      { codec: 'vp9', backend: 'qsv', chroma: ['yuv420', 'yuv444'], hw: true },
      { codec: 'vp9', backend: 'libvpx', chroma: ['yuv420', 'yuv444'], hw: false },
    ],
  })

  it('H.264 4:4:4 needs the browser High 4:4:4 probe AND the agent cell', () => {
    const a = cellAvailability({ cells: nvidiaHost, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(a.h264.yuv444).toMatchObject({ ok: true, reason: 'h264444', hw: true })
    const noProbe = cellAvailability({
      cells: nvidiaHost,
      capsLoaded: true,
      browser: { ...browserAll, h264High444: false },
      failed: new Set(),
    })
    expect(noProbe.h264.yuv444).toMatchObject({ ok: false, reason: 'browserNoH264High444' })
    const intel = cellAvailability({ cells: intelHost, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(intel.h264.yuv444).toMatchObject({ ok: false, reason: 'agentNoH264_444' })
    // A browser that never reported the probe (older view, undefined) reads as no.
    const silent = cellAvailability({
      cells: nvidiaHost,
      capsLoaded: true,
      browser: { av1: true, hevc: true, hevcRext: true, vp9: true },
      failed: new Set(),
    })
    expect(silent.h264.yuv444.ok).toBe(false)
  })

  it('VP9 4:4:4 says hardware encode when a hardware profile-1 cell exists', () => {
    const intel = cellAvailability({ cells: intelHost, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(intel.vp9.yuv444).toMatchObject({ ok: true, reason: 'vp9444hw', hw: true })
    const nvidia = cellAvailability({ cells: nvidiaHost, capsLoaded: true, browser: browserAll, failed: new Set() })
    expect(nvidia.vp9.yuv444).toMatchObject({ ok: true, reason: 'vp9444', hw: false })
  })

  it('the picker maps H.264 + 4:4:4 to its own stored choice and back', () => {
    expect(choiceFromPicker('h264', 'yuv444')).toBe('h264-444')
    expect(choiceFromPicker('h264', 'yuv420')).toBe('h264')
    expect(pickerFromChoice('h264-444')).toEqual({ codec: 'h264', chroma: 'yuv444' })
  })
})
