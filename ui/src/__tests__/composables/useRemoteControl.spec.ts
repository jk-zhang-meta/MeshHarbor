// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest'
import { frameRateAnswerOf } from '@/composables/frameRate'

// Pure helpers exported for testing. We can't import the full composable
// here without mocking the WS store; the helpers below are self-contained
// pure functions and are what actually determine the wire format, so they
// carry the important invariants.
import {
  browserButton,
  grantHoldsRecord,
  openRecordChannel,
  kbdCodeToHid,
  letterboxedNormalise,
  directVideoNormalise,
  extractStatsSnapshot,
  inspectBrowserVideoCodecs,
  base64ToBytes,
  shouldPreventDefault,
  isRemoteSasChord,
  isKeyboardLockSupported,
  filterCapsByPreference,
  resolutionWireMessage,
  RESOLUTION_STORAGE_PREFIX,
  readStoredResolution,
  clampFitDimensions,
  isWebCodecsSupported,
  isVp9_444DecodeSupported,
  isVp9_420DecodeSupported,
  isChromeWithBrokenScriptTransform,
  chunkClipboardText,
  sendClipboardWriteOverDc,
  CLIPBOARD_CHUNK_BYTES,
  CLIPBOARD_MAX_BYTES,
  CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES,
  CLIPBOARD_IMAGE_MAX_BYTES,
  CLIPBOARD_IMG_FRAME_BYTES,
  CLIPBOARD_HTML_MAX_BYTES,
  CLIPBOARD_NATIVE_MAX_BYTES,
  normalizeClipboardText,
  hashClipboardBytes,
  hashClipboardText,
  hashClipboardHtml,
  createClipboardEchoGate,
  createHeldInputTracker,
  createLocalIceOutbox,
  buildClipboardImageFrames,
  grantAllowsClipboard,
  dropClipboardChannel,
  buildClipboardHtmlFrames,
  buildClipboardNativeFrames,
  parseNativeClipPayload,
  bytesToBase64,
  VP9_444_DC_LABEL,
  videoDcOptions,
  storedUnorderedVideo,
  readStoredAudioEnabled,
  persistAudioEnabled,
  audioRequestFields,
  shortCodecFromReceiver,
  codecFromSdp,
  decideKeyAction,
  RC_RECONNECT_LADDER_MS,
  nextReconnectDelayMs,
  deadAirDelayMs,
  RC_PC_DISCONNECTED_GRACE_MS,
  RC_SIGNALING_TIMEOUT_MS,
  RC_WATCHDOG_TICK_MS,
  RC_STALL_PROBE_TICKS,
  RC_STALL_FAIL_TICKS,
  RC_STALL_REPROBE_TICKS,
  RC_STALL_MEDIA_FAIL_TICKS,
  nextDeadTicks,
  transportBytesReceived,
  isRetryableTerminateReason,
  friendlyEndReason,
  endedByHost,
  isRetryableRcErrorCode,
  isFalloutOfEndedSession,
  readyRecoveryAction,
  terminateAction,
  sessionGateAllows,
  nextStallAction,
  nextStallTicks,
  isDeadAir,
  agentIsWaiting,
  advanceEndsWait,
  waitKeptAcrossReconnect,
  isKeptSleepNotice,
  mediaWaitingCopy,
  RC_MEDIA_WAITING_GRACE_MS,
  RC_MEDIA_WAITING_SETTLE_MS,
  classifyDegraded,
  RC_REHOME_MAX_REDIALS,
  rehomeRetryDecision,
  expectedOrgTid,
  turnCredsPath,
  friendlyRcError,
  nextDirPath,
  parseControlInbound,
  hostLockedChipTitle,
  idleSecondsLeft,
  layoutSetWireMessage,
  parseAppsListReply,
  parseAppsActionReply,
  appsListWireMessage,
  appsFocusWireMessage,
  appsLaunchWireMessage,
  decodeStatWireMessage,
  displayMatchWireMessage,
  HeldRequest,
  pickAutoTransport,
  AV1_CODEC_STRING,
  priorityWireMessage,
  codecChoiceToSettings,
  settingsToCodecChoice,
  CODEC_STORAGE_PREFIX,
  readStoredCodecChoice,
  persistCodecChoice,
  RC_CODEC_CHOICES,
  codecConnectAction,
  parseLocalRelayDescriptor,
  localRelayIceServer,
  LOCAL_RELAY_PROBE_PORT,
  LOCAL_RELAY_PROBE_PORTS,
  clipboardBridgeUrl,
  storedDecodePref,
  storedCtxMode,
  storedPerFrameMsg,
  storedFlowParams,
  storedInputGapMs,
  INPUT_GAP_STORAGE_KEY,
  DEFAULT_INPUT_GAP_MS,
  diagHudEnabled,
  remoteCursorCssFor,
  storedSharpenMode,
  storedMetricToggles,
  persistMetricToggles,
  DEFAULT_RC_METRICS,
  storedSharpness,
  HEVC_REXT_CODEC_STRING,
  translateModifierForHost,
  type AutoTransportInputs,
  type KeyDecision,
  type RcCodecChoice,
  resolutionCapAnnotation,
  displayScale,
  resolutionOverrideHint,
  codecLabelFromDecoderConfig,
  captureArmLabel,
} from '@/composables/useRemoteControl'
import {
  computeRenderTarget,
  easuConstants,
  normalizeSharpenMode,
  normalizeSharpness,
  FSR_MAX_SCALE,
  FSR_MAX_AXIS,
  RCAS_ONLY_MAX_SCALE,
  DEFAULT_RCAS_SHARPNESS,
} from '@/workers/rc-fsr-render'
import { codecMimeForShort } from '@/workers/rc-webcodecs-worker'
import { parseFrameHeader, isKeyframe, shouldDecodeFrame } from '@/workers/rc-vp9-444-worker'
import { shouldDecodeFrame as shouldDecodeFrameHevc, classifyCrop } from '@/workers/rc-hevc-worker'
import {
  HopStats,
  StruggleWindow,
  ctxOptionsFor,
  normalizeCtxMode,
  normalizeIntKnob,
  round1,
  bestClockSample,
  clockSample,
  frameAgeMs,
  QueueDrift,
  DEFAULT_MAX_DECODE_QUEUE,
  DEFAULT_STRUGGLE_QUEUE,
  DEFAULT_STRUGGLE_WINDOWS,
} from '@/workers/rc-hop-stats'

function keyEvent(code: string, mods: Partial<{ ctrl: boolean; alt: boolean; meta: boolean; shift: boolean }> = {}): KeyboardEvent {
  return {
    code,
    ctrlKey: !!mods.ctrl,
    altKey: !!mods.alt,
    metaKey: !!mods.meta,
    shiftKey: !!mods.shift,
  } as KeyboardEvent
}

describe('browserButton', () => {
  it.each([
    [0, 'left'],
    [1, 'middle'],
    [2, 'right'],
    [3, 'back'],
    [4, 'forward'],
  ])('maps button %i → %s', (n, expected) => {
    expect(browserButton(n)).toBe(expected)
  })

  it('falls back to left for unknown button indices', () => {
    expect(browserButton(99)).toBe('left')
  })
})

describe('kbdCodeToHid', () => {
  it('maps all 26 letters to the HID keyboard/keypad page', () => {
    // 'KeyA' → 0x04, 'KeyZ' → 0x1d
    expect(kbdCodeToHid('KeyA')).toBe(0x04)
    expect(kbdCodeToHid('KeyM')).toBe(0x04 + 12)
    expect(kbdCodeToHid('KeyZ')).toBe(0x1d)
  })

  it('maps digits 1..9 → 0x1e..0x26 and 0 → 0x27', () => {
    expect(kbdCodeToHid('Digit1')).toBe(0x1e)
    expect(kbdCodeToHid('Digit9')).toBe(0x26)
    expect(kbdCodeToHid('Digit0')).toBe(0x27)
  })

  it('covers navigation + control keys', () => {
    expect(kbdCodeToHid('Enter')).toBe(0x28)
    expect(kbdCodeToHid('Escape')).toBe(0x29)
    expect(kbdCodeToHid('Backspace')).toBe(0x2a)
    expect(kbdCodeToHid('Tab')).toBe(0x2b)
    expect(kbdCodeToHid('Space')).toBe(0x2c)
    expect(kbdCodeToHid('ArrowRight')).toBe(0x4f)
    expect(kbdCodeToHid('ArrowLeft')).toBe(0x50)
    expect(kbdCodeToHid('ArrowDown')).toBe(0x51)
    expect(kbdCodeToHid('ArrowUp')).toBe(0x52)
    expect(kbdCodeToHid('Home')).toBe(0x4a)
    expect(kbdCodeToHid('End')).toBe(0x4d)
    expect(kbdCodeToHid('PageUp')).toBe(0x4b)
    expect(kbdCodeToHid('PageDown')).toBe(0x4e)
    expect(kbdCodeToHid('Insert')).toBe(0x49)
    expect(kbdCodeToHid('Delete')).toBe(0x4c)
  })

  it('maps F1..F12 to the HID function-key range', () => {
    expect(kbdCodeToHid('F1')).toBe(0x3a)
    expect(kbdCodeToHid('F5')).toBe(0x3e)
    expect(kbdCodeToHid('F12')).toBe(0x45)
  })

  it('maps all four sets of modifier keys (L and R)', () => {
    expect(kbdCodeToHid('ControlLeft')).toBe(0xe0)
    expect(kbdCodeToHid('ShiftLeft')).toBe(0xe1)
    expect(kbdCodeToHid('AltLeft')).toBe(0xe2)
    expect(kbdCodeToHid('MetaLeft')).toBe(0xe3)
    expect(kbdCodeToHid('ControlRight')).toBe(0xe4)
    expect(kbdCodeToHid('ShiftRight')).toBe(0xe5)
    expect(kbdCodeToHid('AltRight')).toBe(0xe6)
    expect(kbdCodeToHid('MetaRight')).toBe(0xe7)
  })

  it('returns null for unknown codes', () => {
    expect(kbdCodeToHid('BrowserBack')).toBeNull()
    expect(kbdCodeToHid('MediaPlayPause')).toBeNull()
    expect(kbdCodeToHid('GarbageCode')).toBeNull()
  })

  it('returns null for not-quite-matching shapes', () => {
    // Look-alikes that used to break naive startsWith checks.
    expect(kbdCodeToHid('Keyboard')).toBeNull() // too long for "Key_"
    expect(kbdCodeToHid('Digit10')).toBeNull() // digit out of single-char range
  })

  it('maps the punctuation row to HID usages 0x2d–0x38, 0x35', () => {
    expect(kbdCodeToHid('Backquote')).toBe(0x35)
    expect(kbdCodeToHid('Minus')).toBe(0x2d)
    expect(kbdCodeToHid('Equal')).toBe(0x2e)
    expect(kbdCodeToHid('BracketLeft')).toBe(0x2f)
    expect(kbdCodeToHid('BracketRight')).toBe(0x30)
    expect(kbdCodeToHid('Backslash')).toBe(0x31)
    expect(kbdCodeToHid('Semicolon')).toBe(0x33)
    expect(kbdCodeToHid('Quote')).toBe(0x34)
    expect(kbdCodeToHid('Comma')).toBe(0x36)
    expect(kbdCodeToHid('Period')).toBe(0x37)
    expect(kbdCodeToHid('Slash')).toBe(0x38)
    expect(kbdCodeToHid('IntlBackslash')).toBe(0x64)
  })

  it('maps lock + system keys', () => {
    expect(kbdCodeToHid('CapsLock')).toBe(0x39)
    expect(kbdCodeToHid('NumLock')).toBe(0x53)
    expect(kbdCodeToHid('ScrollLock')).toBe(0x47)
    expect(kbdCodeToHid('PrintScreen')).toBe(0x46)
    expect(kbdCodeToHid('Pause')).toBe(0x48)
    expect(kbdCodeToHid('ContextMenu')).toBe(0x65)
  })

  it('maps the numeric keypad', () => {
    expect(kbdCodeToHid('NumpadDivide')).toBe(0x54)
    expect(kbdCodeToHid('NumpadMultiply')).toBe(0x55)
    expect(kbdCodeToHid('NumpadSubtract')).toBe(0x56)
    expect(kbdCodeToHid('NumpadAdd')).toBe(0x57)
    expect(kbdCodeToHid('NumpadEnter')).toBe(0x58)
    expect(kbdCodeToHid('NumpadDecimal')).toBe(0x63)
    expect(kbdCodeToHid('Numpad1')).toBe(0x59)
    expect(kbdCodeToHid('Numpad9')).toBe(0x61)
    expect(kbdCodeToHid('Numpad0')).toBe(0x62)
  })
})

/**
 * Decision tree that routes a `KeyboardEvent` to either the
 * layout-agnostic KeyText path or the existing HID Key path. Lock the
 * specific routing rules (AltGr, IME, chord-vs-printable, Tab carve-
 * out, keyup suppression) so future regressions in the rule set fail
 * loudly here rather than silently in the field.
 */
describe('decideKeyAction', () => {
  type EvShape = {
    key: string
    code: string
    ctrlKey?: boolean
    altKey?: boolean
    metaKey?: boolean
    shiftKey?: boolean
    isComposing?: boolean
    keyCode?: number
  }
  function ev(shape: EvShape) {
    return {
      key: shape.key,
      code: shape.code,
      ctrlKey: !!shape.ctrlKey,
      altKey: !!shape.altKey,
      metaKey: !!shape.metaKey,
      shiftKey: !!shape.shiftKey,
      isComposing: !!shape.isComposing,
      keyCode: shape.keyCode ?? 0,
    }
  }
  const altGr = (on: boolean) => (k: string) => k === 'AltGraph' && on

  it('US Shift+@ routes via KeyText (no real chord, just Shift)', () => {
    const r = decideKeyAction(
      ev({ key: '@', code: 'Digit2', shiftKey: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'text', text: '@' })
  })

  it('Shift+A (capital letter) routes via KeyText', () => {
    const r = decideKeyAction(
      ev({ key: 'A', code: 'KeyA', shiftKey: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'text', text: 'A' })
  })

  it('DEU/AT AltGr+Q (= "@") routes via KeyText — AltGraph carve-out', () => {
    // Browsers report AltGr as ctrlKey + altKey. Without the
    // AltGraph signal, this would mis-classify as a Ctrl+Alt+Q chord.
    const r = decideKeyAction(
      ev({ key: '@', code: 'KeyQ', ctrlKey: true, altKey: true }),
      true,
      altGr(true),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'text', text: '@' })
  })

  it('Ctrl+C preserves the chord on the HID path (0.1.34 fix lives here)', () => {
    const r = decideKeyAction(
      ev({ key: 'c', code: 'KeyC', ctrlKey: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({
      kind: 'key',
      code: 0x06,
      down: true,
      mods: 0x01,
    })
  })

  it('US-layout intentional Ctrl+Alt+Q stays on the HID path', () => {
    // Real chord: no AltGraph modifier, ev.key reflects the chord
    // (browsers leave it as 'q' for letter chords).
    const r = decideKeyAction(
      ev({ key: 'q', code: 'KeyQ', ctrlKey: true, altKey: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({
      kind: 'key',
      code: 0x14,
      down: true,
      mods: 0x05, // Ctrl | Alt
    })
  })

  it('keyup of a printable+nochord key emits no message', () => {
    const r = decideKeyAction(
      ev({ key: '@', code: 'Digit2', shiftKey: true }),
      false,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'drop' })
  })

  it('Enter routes via HID', () => {
    const r = decideKeyAction(
      ev({ key: 'Enter', code: 'Enter' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'key', code: 0x28, down: true, mods: 0 })
  })

  it('Tab routes via HID even though ev.key is single-char "\\t"', () => {
    // Tab needs a real WM_KEYDOWN(VK_TAB) on the remote so apps that
    // gate focus traversal on it pick it up. KeyText would inject U+0009
    // which doesn't trigger focus change in many forms / IDEs.
    const r = decideKeyAction(
      ev({ key: '\t', code: 'Tab' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'key', code: 0x2b, down: true, mods: 0 })
  })

  it('Space routes via KeyText (length-1 printable)', () => {
    // Pin the choice: if we want Space on the HID path later, this
    // test fails and forces an explicit decision.
    const r = decideKeyAction(
      ev({ key: ' ', code: 'Space' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'text', text: ' ' })
  })

  it('IME composition (isComposing=true) drops without emitting', () => {
    const r = decideKeyAction(
      ev({ key: 'a', code: 'KeyA', isComposing: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'drop' })
  })

  it('Chromium IME placeholder (key="Process", keyCode=229) drops', () => {
    const r = decideKeyAction(
      ev({ key: 'Process', code: 'KeyA', keyCode: 229 }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'drop' })
  })

  it('Auto-repeat: each repeated keydown emits its own KeyText', () => {
    // Browsers fire keydown repeatedly while held. Emit one KeyText
    // per fire — matches local typing behaviour.
    const e = ev({ key: 'a', code: 'KeyA' })
    const r1 = decideKeyAction(e, true, altGr(false))
    const r2 = decideKeyAction(e, true, altGr(false))
    expect(r1).toEqual<KeyDecision>({ kind: 'text', text: 'a' })
    expect(r2).toEqual<KeyDecision>({ kind: 'text', text: 'a' })
  })

  it('Dead-key first stroke (key="Dead") falls to HID via Backquote', () => {
    // Pressing the dead-tilde on a US-International layout. Browsers
    // emit key="Dead" then later emit key="ñ" once the combine fires.
    // The first stroke isn't printable; it should hit the HID path,
    // which only works because Backquote is now in kbdCodeToHid.
    const r = decideKeyAction(
      ev({ key: 'Dead', code: 'Backquote' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'key', code: 0x35, down: true, mods: 0 })
  })

  it('Combined dead-key result (key="ñ") routes via KeyText', () => {
    const r = decideKeyAction(
      ev({ key: 'ñ', code: 'KeyN' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'text', text: 'ñ' })
  })

  it('Unmapped non-printable keys drop without error', () => {
    // BrowserBack has no HID mapping; nothing to send.
    const r = decideKeyAction(
      ev({ key: 'BrowserBack', code: 'BrowserBack' }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({ kind: 'drop' })
  })

  it('Cmd+C on macOS (metaKey) is a real chord', () => {
    // Browsers report Cmd as metaKey. Even with no Ctrl/Alt, metaKey
    // alone counts as a chord — Cmd+C must round-trip as a chord.
    const r = decideKeyAction(
      ev({ key: 'c', code: 'KeyC', metaKey: true }),
      true,
      altGr(false),
    )
    expect(r).toEqual<KeyDecision>({
      kind: 'key',
      code: 0x06,
      down: true,
      mods: 0x08, // Meta
    })
  })
})

describe('letterboxedNormalise', () => {
  // Frame is the outer .video-frame rect; video*  are the <video>'s
  // intrinsic dimensions. object-fit: contain letterboxes the content.
  const frame = { left: 0, top: 0, width: 2560, height: 1600 }

  it('center click at frame center is the video center when aspect matches', () => {
    // 2560×1600 video in 2560×1600 frame: no letterbox, center is 0.5/0.5.
    const r = letterboxedNormalise(1280, 800, frame, 2560, 1600)
    expect(r.x).toBeCloseTo(0.5, 6)
    expect(r.y).toBeCloseTo(0.5, 6)
    expect(r.insideVideo).toBe(true)
  })

  it('ignores clicks in top letterbox when video is wider than frame', () => {
    // 3840×2160 (16:9) in 2560×1600 (16:10) → 80 px black bar top + bottom.
    // A click at y=40 is inside the top letterbox.
    const r = letterboxedNormalise(100, 40, frame, 3840, 2160)
    expect(r.insideVideo).toBe(false)
  })

  it('clicks inside visible region of 16:9 → 16:10 letterbox normalise correctly', () => {
    // 3840×2160 video in 2560×1600 frame: visibleH = 2560/(16/9) = 1440;
    // top offset = (1600-1440)/2 = 80. Click at frame (1280, 800) is the
    // center: localY = 800-80 = 720, y = 720/1440 = 0.5. Good.
    const r = letterboxedNormalise(1280, 800, frame, 3840, 2160)
    expect(r.x).toBeCloseTo(0.5, 6)
    expect(r.y).toBeCloseTo(0.5, 6)
    expect(r.insideVideo).toBe(true)
  })

  it('clicks inside visible region of taller-than-wide video normalise correctly', () => {
    // 1080×1920 portrait video in 2560×1600 frame: visibleW = 1600*(1080/1920) = 900;
    // left offset = (2560-900)/2 = 830. Click at (830+450, 800) is center of content.
    const r = letterboxedNormalise(830 + 450, 800, frame, 1080, 1920)
    expect(r.x).toBeCloseTo(0.5, 6)
    expect(r.y).toBeCloseTo(0.5, 6)
    expect(r.insideVideo).toBe(true)
  })

  it('falls back to frame-relative coords before first decoded frame', () => {
    // videoWidth=0 means no stream intrinsic yet — normalise against frame.
    const r = letterboxedNormalise(640, 400, frame, 0, 0)
    expect(r.x).toBeCloseTo(0.25, 6)
    expect(r.y).toBeCloseTo(0.25, 6)
    expect(r.insideVideo).toBe(true)
  })

  it('clamps out-of-frame clicks to [0,1]', () => {
    const r = letterboxedNormalise(-100, 5000, frame, 2560, 1600)
    expect(r.x).toBeGreaterThanOrEqual(0)
    expect(r.x).toBeLessThanOrEqual(1)
    expect(r.y).toBeGreaterThanOrEqual(0)
    expect(r.y).toBeLessThanOrEqual(1)
  })
})

describe('extractStatsSnapshot', () => {
  /**
   * Build a fake `RTCStatsReport`: a `Map<string, RTCStats>` with the
   * shape the browser emits. Only the fields the helper reads are
   * populated; missing fields exercise the helper's fallback paths.
   */
  function makeReport(
    entries: Array<[string, Record<string, unknown>]>,
  ): RTCStatsReport {
    const map = new Map<string, Record<string, unknown>>()
    for (const [id, stats] of entries) map.set(id, { id, ...stats })
    return map as unknown as RTCStatsReport
  }

  it('returns bitrate=0 on first call (no previous snapshot)', () => {
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 100_000, timestamp: 1_000, framesPerSecond: 30,
        codecId: 'Codec_H264',
      }],
      ['Codec_H264', { type: 'codec', mimeType: 'video/H264' }],
    ])
    const snap = extractStatsSnapshot(report, 0, 0)
    expect(snap.next.bitrate_bps).toBe(0)
    expect(snap.next.fps).toBe(30)
    expect(snap.next.codec).toBe('H264')
    expect(snap.bytes).toBe(100_000)
    expect(snap.tsMs).toBe(1_000)
  })

  it('computes bitrate from byte/timestamp delta on second call', () => {
    // 100 KB new bytes over 500 ms = 100_000 bytes × 8 / 0.5 s = 1_600_000 bps
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 200_000, timestamp: 1_500, framesPerSecond: 59.9,
        codecId: 'Codec_H265',
      }],
      ['Codec_H265', { type: 'codec', mimeType: 'video/H265' }],
    ])
    const snap = extractStatsSnapshot(report, 100_000, 1_000)
    expect(snap.next.bitrate_bps).toBe(1_600_000)
    expect(snap.next.fps).toBe(59.9)
    expect(snap.next.codec).toBe('H265')
  })

  it('rounds fps to one decimal', () => {
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 0, timestamp: 0, framesPerSecond: 29.876,
        codecId: 'Codec_X',
      }],
      ['Codec_X', { type: 'codec', mimeType: 'video/AV1' }],
    ])
    const snap = extractStatsSnapshot(report, 0, 0)
    expect(snap.next.fps).toBe(29.9)
    expect(snap.next.codec).toBe('AV1')
  })

  it('treats missing codec entry as empty string', () => {
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 0, timestamp: 1_000, framesPerSecond: 0,
        codecId: 'Codec_Unmatched',
      }],
      // no `Codec_Unmatched` entry
    ])
    const snap = extractStatsSnapshot(report, 0, 0)
    expect(snap.next.codec).toBe('')
  })

  it('ignores non-video inbound-rtp (audio) and non-inbound streams', () => {
    const report = makeReport([
      ['RTCInboundAudio_0', {
        type: 'inbound-rtp', kind: 'audio',
        bytesReceived: 99_999, timestamp: 1_000,
      }],
      ['RTCOutboundVideo_0', {
        type: 'outbound-rtp', kind: 'video',
        bytesSent: 12_345, timestamp: 1_000,
      }],
    ])
    const snap = extractStatsSnapshot(report, 0, 0)
    expect(snap.bytes).toBe(0)
    expect(snap.tsMs).toBe(0)
    expect(snap.next).toEqual({ bitrate_bps: 0, fps: 0, codec: '' })
  })

  it('clamps negative byte deltas to 0 (e.g. counter reset on renegotiation)', () => {
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 500, timestamp: 2_000, framesPerSecond: 30,
        codecId: 'Codec_H264',
      }],
      ['Codec_H264', { type: 'codec', mimeType: 'video/H264' }],
    ])
    const snap = extractStatsSnapshot(report, 1_000_000, 1_000)
    expect(snap.next.bitrate_bps).toBe(0)
  })

  it('strips the "video/" prefix case-insensitively', () => {
    const report = makeReport([
      ['RTCInboundVideo_0', {
        type: 'inbound-rtp', kind: 'video',
        bytesReceived: 0, timestamp: 0, framesPerSecond: 0,
        codecId: 'C',
      }],
      ['C', { type: 'codec', mimeType: 'VIDEO/VP9' }],
    ])
    const snap = extractStatsSnapshot(report, 0, 0)
    expect(snap.next.codec).toBe('VP9')
  })
})

describe('inspectBrowserVideoCodecs', () => {
  // Stub `RTCRtpReceiver.getCapabilities` for each test case. jsdom
  // (vitest's default DOM) doesn't ship a real WebRTC API.
  const realRTC = (globalThis as unknown as { RTCRtpReceiver?: unknown }).RTCRtpReceiver

  function stubCapabilities(codecs: Array<{ mimeType: string }>) {
    ;(globalThis as unknown as { RTCRtpReceiver: unknown }).RTCRtpReceiver = {
      getCapabilities: (kind: string) => {
        if (kind !== 'video') return null
        return { codecs }
      },
    }
  }

  function unsetCapabilities() {
    delete (globalThis as unknown as { RTCRtpReceiver?: unknown }).RTCRtpReceiver
  }

  beforeEach(() => {
    unsetCapabilities()
  })

  afterAll(() => {
    if (realRTC) {
      ;(globalThis as unknown as { RTCRtpReceiver: unknown }).RTCRtpReceiver = realRTC
    } else {
      unsetCapabilities()
    }
  })

  it('returns empty array when getCapabilities is unavailable', () => {
    expect(inspectBrowserVideoCodecs()).toEqual([])
  })

  it('returns empty array when getCapabilities returns no codecs', () => {
    stubCapabilities([])
    expect(inspectBrowserVideoCodecs()).toEqual([])
  })

  it('extracts known codecs and strips the video/ prefix', () => {
    stubCapabilities([
      { mimeType: 'video/H264' },
      { mimeType: 'video/VP8' },
    ])
    const out = inspectBrowserVideoCodecs()
    expect(out.sort()).toEqual(['h264', 'vp8'])
  })

  it('deduplicates multiple profile-level-id variants of the same codec', () => {
    stubCapabilities([
      { mimeType: 'video/H264' },
      { mimeType: 'video/H264' },
      { mimeType: 'video/H264' },
    ])
    expect(inspectBrowserVideoCodecs()).toEqual(['h264'])
  })

  it('filters out RTP mechanism codecs (rtx, red, ulpfec)', () => {
    stubCapabilities([
      { mimeType: 'video/H264' },
      { mimeType: 'video/rtx' },
      { mimeType: 'video/red' },
      { mimeType: 'video/ulpfec' },
      { mimeType: 'video/flexfec-03' },
    ])
    expect(inspectBrowserVideoCodecs()).toEqual(['h264'])
  })

  it('handles all five negotiable codecs', () => {
    stubCapabilities([
      { mimeType: 'video/H264' },
      { mimeType: 'video/H265' },
      { mimeType: 'video/AV1' },
      { mimeType: 'video/VP9' },
      { mimeType: 'video/VP8' },
    ])
    expect(inspectBrowserVideoCodecs().sort()).toEqual([
      'av1',
      'h264',
      'h265',
      'vp8',
      'vp9',
    ])
  })
})

describe('base64ToBytes', () => {
  it('round-trips an all-zero buffer', () => {
    // 8 zero bytes → base64 "AAAAAAAAAAA="
    const bytes = base64ToBytes('AAAAAAAAAAA=')
    expect(bytes.length).toBe(8)
    for (const b of bytes) expect(b).toBe(0)
  })

  it('decodes a single-byte buffer', () => {
    // 0xFF → "/w=="
    expect(Array.from(base64ToBytes('/w=='))).toEqual([0xff])
  })

  it('decodes a BGRA cursor-shape-sized buffer', () => {
    // 32×32 BGRA = 4096 bytes of alternating pattern. Agent encodes
    // this as base64 over the `cursor` data channel (1E.2); the
    // decoder must round-trip byte-exactly.
    const raw = new Uint8Array(4096)
    for (let i = 0; i < raw.length; i++) raw[i] = (i * 31) & 0xff
    // encode via btoa
    let bin = ''
    for (const b of raw) bin += String.fromCharCode(b)
    const b64 = btoa(bin)
    const out = base64ToBytes(b64)
    expect(out.length).toBe(raw.length)
    for (let i = 0; i < raw.length; i++) expect(out[i]).toBe(raw[i])
  })
})

describe('shouldPreventDefault', () => {
  it('always intercepts Tab', () => {
    expect(shouldPreventDefault(keyEvent('Tab'), false)).toBe(true)
    expect(shouldPreventDefault(keyEvent('Tab'), true)).toBe(true)
  })

  it('intercepts plain Backspace but not when modifiers are held', () => {
    expect(shouldPreventDefault(keyEvent('Backspace'), false)).toBe(true)
    expect(shouldPreventDefault(keyEvent('Backspace', { ctrl: true }), false)).toBe(false)
    expect(shouldPreventDefault(keyEvent('Backspace', { alt: true }), false)).toBe(false)
    expect(shouldPreventDefault(keyEvent('Backspace', { meta: true }), false)).toBe(false)
  })

  it('intercepts browser-eaten shortcuts only when pointer is over video', () => {
    for (const code of ['KeyA', 'KeyC', 'KeyV', 'KeyX', 'KeyZ', 'KeyY', 'KeyF', 'KeyS', 'KeyP', 'KeyR']) {
      // Pointer outside the viewer → the controller still gets normal
      // browser shortcuts (Ctrl+T to open a tab, etc.).
      expect(shouldPreventDefault(keyEvent(code, { ctrl: true }), false)).toBe(false)
      // Pointer over the viewer → intercept so the shortcut forwards
      // to the remote without triggering the local browser UI.
      expect(shouldPreventDefault(keyEvent(code, { ctrl: true }), true)).toBe(true)
      // Cmd (meta) is accepted as the same prefix on macOS.
      expect(shouldPreventDefault(keyEvent(code, { meta: true }), true)).toBe(true)
    }
  })

  it('lets untouched Ctrl+T / Ctrl+W through even when pointer inside (NOT keyboard-locked)', () => {
    // Explicitly NOT in the intercept list — these are still the user's
    // own browser tab/window controls when the keyboard is unlocked.
    // Forwarding them to the remote over the input DC is fine, but we
    // don't want to also preventDefault. (Locked fullscreen flips this
    // — see the keyboardLocked suite below.)
    expect(shouldPreventDefault(keyEvent('KeyT', { ctrl: true }), true)).toBe(false)
    expect(shouldPreventDefault(keyEvent('KeyW', { ctrl: true }), true)).toBe(false)
  })

  it('does not intercept a bare letter keypress without modifiers', () => {
    expect(shouldPreventDefault(keyEvent('KeyA'), true)).toBe(false)
    expect(shouldPreventDefault(keyEvent('KeyZ', { shift: true }), true)).toBe(false)
  })

  it('explicit keyboardLocked=false behaves exactly like the two-arg form', () => {
    // Default-param regression guard: every call above relies on the
    // third parameter defaulting to false.
    expect(shouldPreventDefault(keyEvent('KeyW', { ctrl: true }), true, false)).toBe(false)
    expect(shouldPreventDefault(keyEvent('KeyA'), true, false)).toBe(false)
  })

  it('keyboardLocked=true suppresses the local default for EVERY key', () => {
    // Locked fullscreen (Keyboard Lock API active): Alt+Tab, Win,
    // Ctrl+W/T, F-keys, Escape and bare letters all forward to the
    // remote — nothing may run a local browser default. pointerInside
    // is irrelevant in this mode (it can be stale right after
    // entering fullscreen via the toolbar button).
    for (const inside of [true, false]) {
      expect(shouldPreventDefault(keyEvent('KeyW', { ctrl: true }), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('KeyT', { ctrl: true }), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('F5'), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('Escape'), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('KeyA'), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('MetaLeft', { meta: true }), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('Tab'), inside, true)).toBe(true)
      expect(shouldPreventDefault(keyEvent('AltLeft', { alt: true }), inside, true)).toBe(true)
    }
  })
})

describe('isRemoteSasChord', () => {
  function chord(
    code: string,
    mods: { ctrl?: boolean; alt?: boolean; meta?: boolean } = {},
  ): Pick<KeyboardEvent, 'code' | 'ctrlKey' | 'altKey' | 'metaKey'> {
    return {
      code,
      ctrlKey: mods.ctrl ?? false,
      altKey: mods.alt ?? false,
      metaKey: mods.meta ?? false,
    }
  }

  it('accepts Ctrl+Alt+End (RDP convention) and the literal Ctrl+Alt+Delete', () => {
    expect(isRemoteSasChord(chord('End', { ctrl: true, alt: true }))).toBe(true)
    expect(isRemoteSasChord(chord('Delete', { ctrl: true, alt: true }))).toBe(true)
  })

  it('rejects partial chords and other keys', () => {
    expect(isRemoteSasChord(chord('End', { ctrl: true }))).toBe(false)
    expect(isRemoteSasChord(chord('End', { alt: true }))).toBe(false)
    expect(isRemoteSasChord(chord('End'))).toBe(false)
    expect(isRemoteSasChord(chord('KeyE', { ctrl: true, alt: true }))).toBe(false)
  })

  it('rejects when Meta is also held (Win+Ctrl+Alt combos)', () => {
    expect(isRemoteSasChord(chord('End', { ctrl: true, alt: true, meta: true }))).toBe(false)
  })

  it('AltGraph carve-out: AltGr+End must not fire a SAS', () => {
    // German & co. AltGr layouts report ctrlKey+altKey on AltGr.
    expect(
      isRemoteSasChord(chord('End', { ctrl: true, alt: true }), (k) => k === 'AltGraph'),
    ).toBe(false)
  })
})

describe('isKeyboardLockSupported', () => {
  it('false without a navigator or a keyboard object', () => {
    expect(isKeyboardLockSupported(undefined)).toBe(false)
    expect(isKeyboardLockSupported({})).toBe(false)
  })

  it('false when keyboard exists but lock is missing (non-Chromium)', () => {
    expect(isKeyboardLockSupported({ keyboard: {} })).toBe(false)
  })

  it('true when keyboard.lock is a function (Chromium secure context)', () => {
    expect(isKeyboardLockSupported({ keyboard: { lock: async () => {} } })).toBe(true)
  })
})

describe('filterCapsByPreference', () => {
  const all = ['av1', 'h265', 'vp9', 'h264', 'vp8']

  it('passes the full list through when no override is set', () => {
    expect(filterCapsByPreference(all, null)).toEqual(all)
  })

  it('narrows to the preferred codec plus H.264 as a parachute', () => {
    expect(filterCapsByPreference(all, 'h265')).toEqual(['h265', 'h264'])
    expect(filterCapsByPreference(all, 'av1')).toEqual(['av1', 'h264'])
    expect(filterCapsByPreference(all, 'vp9')).toEqual(['vp9', 'h264'])
  })

  it('omits the H.264 parachute when H.264 is the preference itself', () => {
    expect(filterCapsByPreference(all, 'h264')).toEqual(['h264'])
  })

  it('returns just the preferred codec when the browser does not support H.264', () => {
    expect(filterCapsByPreference(['h265', 'vp9'], 'h265')).toEqual(['h265'])
  })

  it('falls back to just the H.264 parachute when the preferred codec is absent but H.264 is available', () => {
    expect(filterCapsByPreference(['h264', 'vp9'], 'av1')).toEqual(['h264'])
  })

  it('returns empty when neither the preferred codec nor H.264 is advertised', () => {
    // Forcing AV1 on a Firefox that offers neither AV1 nor H.264 will
    // fail to negotiate. That's by design — the operator sees the
    // filtered caps in the console log and can clear the override.
    expect(filterCapsByPreference(['vp9'], 'av1')).toEqual([])
  })
})

describe('directVideoNormalise', () => {
  // Viewer pixel (clientX, clientY) → [0,1] normalised, mapped against a
  // video element whose bounding rect is known. This is the mapper used
  // for `scale-original` and `scale-custom` modes, where no letterbox
  // math is needed because the <video> is rendered at its intrinsic
  // (scroll + scale) dimensions.

  const rect = { left: 10, top: 20, width: 1920, height: 1080 }

  it('maps top-left to (0,0)', () => {
    expect(directVideoNormalise(10, 20, rect)).toEqual({
      x: 0, y: 0, insideVideo: true,
    })
  })

  it('maps bottom-right to (1,1)', () => {
    const out = directVideoNormalise(1930, 1100, rect)
    expect(out.x).toBeCloseTo(1, 6)
    expect(out.y).toBeCloseTo(1, 6)
    expect(out.insideVideo).toBe(true)
  })

  it('reports outside when the pointer is before the rect', () => {
    const out = directVideoNormalise(0, 0, rect)
    expect(out.insideVideo).toBe(false)
    // Coordinates clamped to [0,1] regardless.
    expect(out.x).toBe(0)
    expect(out.y).toBe(0)
  })

  it('reports outside when the pointer is past the rect', () => {
    const out = directVideoNormalise(2500, 2500, rect)
    expect(out.insideVideo).toBe(false)
    expect(out.x).toBe(1)
    expect(out.y).toBe(1)
  })

  it('works at custom-scale sizes — mapping stays [0,1] vs the rendered rect', () => {
    // Remote is 1920x1080, custom scale 200% → rendered 3840x2160.
    // Middle of that rendered rect should still normalise to (0.5, 0.5)
    // — the agent doesn't care about scale; it gets normalised coords.
    const scaled = { left: 0, top: 0, width: 3840, height: 2160 }
    const out = directVideoNormalise(1920, 1080, scaled)
    expect(out.x).toBeCloseTo(0.5, 6)
    expect(out.y).toBeCloseTo(0.5, 6)
    expect(out.insideVideo).toBe(true)
  })

  it('returns a safe fallback when the rect has zero dimensions', () => {
    const zero = { left: 0, top: 0, width: 0, height: 0 }
    expect(directVideoNormalise(100, 100, zero)).toEqual({
      x: 0, y: 0, insideVideo: false,
    })
  })
})

describe('resolutionWireMessage', () => {
  // Locks the exact JSON shape the agent's control-DC handler parses.
  // Changing these assertions without changing the agent-side
  // `rc:resolution` match arms in `peer.rs::attach_control_handler`
  // will break the feature in the field.

  it('emits original with no dims', () => {
    expect(resolutionWireMessage({ mode: 'original' })).toEqual({
      t: 'rc:resolution',
      mode: 'original',
    })
  })

  it('emits fit with width + height', () => {
    expect(resolutionWireMessage({ mode: 'fit', width: 1920, height: 1080 })).toEqual({
      t: 'rc:resolution',
      mode: 'fit',
      width: 1920,
      height: 1080,
    })
  })

  it('emits custom with width + height', () => {
    expect(resolutionWireMessage({ mode: 'custom', width: 2560, height: 1440 })).toEqual({
      t: 'rc:resolution',
      mode: 'custom',
      width: 2560,
      height: 1440,
    })
  })

  it('rounds non-integer dims to the nearest pixel', () => {
    // devicePixelRatio + rect math can produce fractional CSS pixels.
    // The wire format is u32 — round at the browser boundary.
    expect(resolutionWireMessage({ mode: 'fit', width: 1920.7, height: 1080.2 })).toEqual({
      t: 'rc:resolution',
      mode: 'fit',
      width: 1921,
      height: 1080,
    })
  })

  it('drops invalid custom/fit with missing or zero dims', () => {
    expect(resolutionWireMessage({ mode: 'fit' })).toBeNull()
    expect(resolutionWireMessage({ mode: 'custom', width: 0, height: 100 })).toBeNull()
    expect(resolutionWireMessage({ mode: 'custom', width: 100, height: 0 })).toBeNull()
  })

  it('defaults readStoredResolution to fit when no manual preference is stored', () => {
    const aid = '69c92d8f011ff058c228e0d0'
    globalThis.localStorage?.removeItem(RESOLUTION_STORAGE_PREFIX + aid)
    expect(readStoredResolution(aid)).toEqual({ mode: 'fit' })

    globalThis.localStorage?.setItem(
      RESOLUTION_STORAGE_PREFIX + aid,
      JSON.stringify({ mode: 'original' }),
    )
    expect(readStoredResolution(aid)).toEqual({
      mode: 'original',
      width: undefined,
      height: undefined,
    })

    globalThis.localStorage?.setItem(
      RESOLUTION_STORAGE_PREFIX + aid,
      JSON.stringify({ mode: 'custom', width: 1280, height: 800 }),
    )
    expect(readStoredResolution(aid)).toEqual({
      mode: 'custom',
      width: 1280,
      height: 800,
    })
    globalThis.localStorage?.removeItem(RESOLUTION_STORAGE_PREFIX + aid)
  })

  it('clamps fit dimensions to even values and never upscales above native dims', () => {
    expect(clampFitDimensions(1256.4, 720.8)).toEqual({ width: 1256, height: 720 })
    expect(clampFitDimensions(1257, 721)).toEqual({ width: 1256, height: 720 })
    expect(clampFitDimensions(2536, 1520, 1920, 1200)).toEqual({ width: 1920, height: 1200 })
    expect(clampFitDimensions(2536, 1000, 1920, 1200)).toEqual({ width: 1920, height: 1000 })
  })
})

describe('codecMimeForShort', () => {
  it('maps the known codec short-names to permissive WebCodecs strings', () => {
    expect(codecMimeForShort('h264')).toBe('avc1.42E01F')
    expect(codecMimeForShort('h265')).toBe('hev1.1.6.L153.B0')
    expect(codecMimeForShort('hevc')).toBe('hev1.1.6.L153.B0')
    expect(codecMimeForShort('av1')).toBe('av01.0.08M.08')
    expect(codecMimeForShort('vp9')).toBe('vp09.00.10.08')
    expect(codecMimeForShort('vp8')).toBe('vp8')
  })

  it('is case-insensitive', () => {
    expect(codecMimeForShort('H264')).toBe('avc1.42E01F')
    expect(codecMimeForShort('HEVC')).toBe('hev1.1.6.L153.B0')
  })

  it('falls back to H.264 for unknown short-names so a typo or stale wire value still produces a valid decoder config', () => {
    expect(codecMimeForShort('bogus')).toBe('avc1.42E01F')
    expect(codecMimeForShort('')).toBe('avc1.42E01F')
  })
})

describe('isWebCodecsSupported', () => {
  const originalTransform = (globalThis as unknown as { RTCRtpScriptTransform?: unknown }).RTCRtpScriptTransform
  const originalDecoder = (globalThis as unknown as { VideoDecoder?: unknown }).VideoDecoder
  afterAll(() => {
    ;(globalThis as unknown as Record<string, unknown>).RTCRtpScriptTransform = originalTransform
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = originalDecoder
  })

  it('returns false when either API is missing (jsdom baseline)', () => {
    delete (globalThis as unknown as Record<string, unknown>).RTCRtpScriptTransform
    delete (globalThis as unknown as Record<string, unknown>).VideoDecoder
    expect(isWebCodecsSupported()).toBe(false)
  })

  it('returns false when only one of the two is present — Firefox-like with VideoDecoder but no RTCRtpScriptTransform', () => {
    ;(globalThis as unknown as Record<string, unknown>).RTCRtpScriptTransform = undefined
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = function VideoDecoder() {}
    expect(isWebCodecsSupported()).toBe(false)
  })

  it('returns true when both APIs are constructors — Chrome 94+ surface', () => {
    ;(globalThis as unknown as Record<string, unknown>).RTCRtpScriptTransform = function RTCRtpScriptTransform() {}
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = function VideoDecoder() {}
    expect(isWebCodecsSupported()).toBe(true)
  })
})

describe('isVp9_420DecodeSupported (#2231)', () => {
  const originalDecoder = (globalThis as unknown as { VideoDecoder?: unknown }).VideoDecoder
  afterAll(() => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = originalDecoder
  })

  it('returns false when VideoDecoder is missing', async () => {
    delete (globalThis as unknown as Record<string, unknown>).VideoDecoder
    await expect(isVp9_420DecodeSupported()).resolves.toBe(false)
  })

  it('asks for VP9 profile 0 (the string the worker configures at 4:2:0) and returns its answer', async () => {
    const asked: string[] = []
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = {
      isConfigSupported: async (cfg: { codec: string }) => {
        asked.push(cfg.codec)
        // Firefox's WebCodecs: profile 0 yes, profile 1 no.
        return { supported: cfg.codec === 'vp09.00.10.08' }
      },
    }
    await expect(isVp9_420DecodeSupported()).resolves.toBe(true)
    await expect(isVp9_444DecodeSupported()).resolves.toBe(false)
    expect(asked).toEqual(['vp09.00.10.08', 'vp09.01.10.08'])
  })

  it('returns false when isConfigSupported throws', async () => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = {
      isConfigSupported: async () => {
        throw new TypeError('unsupported')
      },
    }
    await expect(isVp9_420DecodeSupported()).resolves.toBe(false)
  })
})

describe('isVp9_444DecodeSupported', () => {
  const originalDecoder = (globalThis as unknown as { VideoDecoder?: unknown }).VideoDecoder
  afterAll(() => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = originalDecoder
  })

  it('returns false when VideoDecoder is missing (Firefox / older Safari)', async () => {
    delete (globalThis as unknown as Record<string, unknown>).VideoDecoder
    await expect(isVp9_444DecodeSupported()).resolves.toBe(false)
  })

  it('returns false when VideoDecoder lacks isConfigSupported', async () => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = function VideoDecoder() {}
    await expect(isVp9_444DecodeSupported()).resolves.toBe(false)
  })

  it('queries isConfigSupported with the canonical VP9 profile 1 8-bit codec string and returns its supported flag', async () => {
    let observedCodec = ''
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = {
      isConfigSupported: async (cfg: { codec: string }) => {
        observedCodec = cfg.codec
        return { supported: true }
      },
    }
    await expect(isVp9_444DecodeSupported()).resolves.toBe(true)
    // vp09.<profile=01>.<level=10>.<bit_depth=08> — Profile 1 is the
    // 4:4:4 path; locking the exact string keeps the worker's
    // VideoDecoder.configure call in lockstep with this probe.
    expect(observedCodec).toBe('vp09.01.10.08')
  })

  it('returns false when isConfigSupported reports unsupported', async () => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = {
      isConfigSupported: async () => ({ supported: false }),
    }
    await expect(isVp9_444DecodeSupported()).resolves.toBe(false)
  })

  it('swallows isConfigSupported throws and returns false', async () => {
    ;(globalThis as unknown as Record<string, unknown>).VideoDecoder = {
      isConfigSupported: async () => { throw new Error('boom') },
    }
    await expect(isVp9_444DecodeSupported()).resolves.toBe(false)
  })
})

describe('isChromeWithBrokenScriptTransform (rc.43)', () => {
  const originalNav = globalThis.navigator
  function setNav(stub: unknown) {
    Object.defineProperty(globalThis, 'navigator', {
      value: stub,
      configurable: true,
      writable: true,
    })
  }
  afterAll(() => {
    Object.defineProperty(globalThis, 'navigator', {
      value: originalNav,
      configurable: true,
      writable: true,
    })
  })

  it('returns false when userAgentData brand is Chrome 147', () => {
    setNav({
      userAgentData: { brands: [{ brand: 'Google Chrome', version: '147' }] },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/147.0.0.0',
    })
    expect(isChromeWithBrokenScriptTransform()).toBe(false)
  })

  it('returns true when userAgentData brand is Chromium 148 (field repro)', () => {
    setNav({
      userAgentData: {
        brands: [
          { brand: 'Chromium', version: '148' },
          { brand: 'Google Chrome', version: '148' },
          { brand: 'Not/A)Brand', version: '99' },
        ],
      },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/148.0.0.0',
    })
    expect(isChromeWithBrokenScriptTransform()).toBe(true)
  })

  it('returns true when userAgentData missing but userAgent reports Chrome 149', () => {
    setNav({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/149.0.7000.0',
    })
    expect(isChromeWithBrokenScriptTransform()).toBe(true)
  })

  it('returns false when neither brands nor Chrome UA token are present (Firefox/Safari)', () => {
    setNav({
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/130.0',
    })
    expect(isChromeWithBrokenScriptTransform()).toBe(false)
  })

  it('returns false when navigator is undefined (worker / SSR)', () => {
    setNav(undefined)
    expect(isChromeWithBrokenScriptTransform()).toBe(false)
  })
})

describe('chunkClipboardText (rc.44)', () => {
  it('returns a single-element array for empty input', () => {
    expect(chunkClipboardText('')).toEqual([''])
  })

  it('returns the input as a single chunk when it fits the budget', () => {
    expect(chunkClipboardText('hello')).toEqual(['hello'])
  })

  it('splits long ASCII at CLIPBOARD_CHUNK_BYTES boundaries', () => {
    const text = 'a'.repeat(CLIPBOARD_CHUNK_BYTES * 3 + 7)
    const chunks = chunkClipboardText(text)
    expect(chunks.length).toBe(4)
    // Every chunk except possibly the last is exactly CHUNK_BYTES bytes.
    const enc = new TextEncoder()
    for (let i = 0; i < chunks.length - 1; i++) {
      expect(enc.encode(chunks[i]).byteLength).toBeLessThanOrEqual(CLIPBOARD_CHUNK_BYTES)
    }
    // Round-trip: simple concatenation reproduces the input.
    expect(chunks.join('')).toBe(text)
  })

  it('preserves UTF-8 codepoint boundaries even when a 4-byte char straddles the split', () => {
    // Fill to (CHUNK_BYTES - 2) ASCII, then insert a 4-byte codepoint
    // (🦀). Natural split at CHUNK_BYTES would land inside the crab;
    // chunker must walk back to keep the codepoint whole.
    const prefix = 'a'.repeat(CLIPBOARD_CHUNK_BYTES - 2)
    const text = prefix + '🦀b'
    const chunks = chunkClipboardText(text)
    expect(chunks.join('')).toBe(text)
    // Each chunk must be a valid UTF-8 string (no replacement chars).
    const dec = new TextDecoder('utf-8', { fatal: true })
    const enc = new TextEncoder()
    for (const c of chunks) {
      // Round-tripping through fatal decoder throws on partial sequences.
      expect(() => dec.decode(enc.encode(c))).not.toThrow()
      expect(enc.encode(c).byteLength).toBeLessThanOrEqual(CLIPBOARD_CHUNK_BYTES)
    }
  })

  it('handles an entirely multi-byte payload (all-emoji stress test)', () => {
    // 5000 × 🦀 = 20000 bytes UTF-8 > CHUNK_BYTES (14336)
    const text = '🦀'.repeat(5000)
    const chunks = chunkClipboardText(text)
    expect(chunks.length).toBeGreaterThanOrEqual(2)
    expect(chunks.join('')).toBe(text)
    const enc = new TextEncoder()
    for (const c of chunks) {
      expect(enc.encode(c).byteLength).toBeLessThanOrEqual(CLIPBOARD_CHUNK_BYTES)
    }
  })
})

describe('sendClipboardWriteOverDc (rc.44)', () => {
  // Stub DC capturing every `.send()` call so we can assert wire shape
  // without a real RTCDataChannel. The function under test only reads
  // `readyState` indirectly (not at all in the body) — caller's
  // responsibility — so we don't need to stub that.
  function makeStubDc() {
    const sent: string[] = []
    return {
      sent,
      ch: {
        send: (s: string) => {
          sent.push(s)
        },
      } as unknown as RTCDataChannel,
    }
  }

  it('uses single-envelope clipboard:write for small ASCII text (with a v2 id)', () => {
    const { ch, sent } = makeStubDc()
    const res = sendClipboardWriteOverDc(ch, 'hello world')
    expect(res.envelopes).toBe(1)
    expect(sent.length).toBe(1)
    const parsed = JSON.parse(sent[0])
    expect(parsed.t).toBe('clipboard:write')
    expect(parsed.text).toBe('hello world')
    // v2 — every write carries an id so v2 agents can ack it. Old
    // agents ignore the unknown field (no deny_unknown_fields).
    expect(typeof parsed.id).toBe('string')
    expect(parsed.id).toBe(res.id)
  })

  it('sends the text RAW — CRLF preserved for v1 agents that write verbatim', () => {
    const { ch, sent } = makeStubDc()
    sendClipboardWriteOverDc(ch, 'line1\r\nline2')
    const parsed = JSON.parse(sent[0])
    expect(parsed.text).toBe('line1\r\nline2')
  })

  it('uses single-envelope clipboard:write right at the threshold', () => {
    const { ch, sent } = makeStubDc()
    const text = 'a'.repeat(CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES)
    const res = sendClipboardWriteOverDc(ch, text)
    expect(res.envelopes).toBe(1)
    const parsed = JSON.parse(sent[0])
    expect(parsed.t).toBe('clipboard:write')
  })

  it('switches to clipboard:write-chunk when above the threshold', () => {
    const { ch, sent } = makeStubDc()
    const text = 'a'.repeat(CLIPBOARD_SINGLE_ENVELOPE_THRESHOLD_BYTES + 1)
    const res = sendClipboardWriteOverDc(ch, text)
    expect(res.envelopes).toBeGreaterThanOrEqual(1)
    expect(sent.length).toBe(res.envelopes)
    const first = JSON.parse(sent[0])
    expect(first.t).toBe('clipboard:write-chunk')
    expect(typeof first.id).toBe('string')
    expect(first.id).toBe(res.id)
    expect(first.seq).toBe(0)
    expect(first.last).toBe(res.envelopes === 1)
  })

  it('chunked envelopes share an id and have sequential seq + final last=true', () => {
    const { ch, sent } = makeStubDc()
    // Force 3+ chunks: 3 × CHUNK_BYTES of ASCII.
    const text = 'a'.repeat(CLIPBOARD_CHUNK_BYTES * 3)
    sendClipboardWriteOverDc(ch, text)
    const envelopes = sent.map((s) => JSON.parse(s))
    const ids = new Set(envelopes.map((e) => e.id))
    expect(ids.size).toBe(1)
    envelopes.forEach((e, i) => {
      expect(e.t).toBe('clipboard:write-chunk')
      expect(e.seq).toBe(i)
      expect(e.last).toBe(i + 1 === envelopes.length)
    })
    // Concatenation of `text` across chunks must reproduce the input —
    // this is the load-bearing invariant for the agent's reassembler.
    expect(envelopes.map((e) => e.text).join('')).toBe(text)
  })

  it('truncates and warns when input exceeds the 1 MB hard cap', () => {
    const { ch, sent } = makeStubDc()
    const text = 'a'.repeat(CLIPBOARD_MAX_BYTES + 50_000)
    const warnings: string[] = []
    const originalWarn = console.warn
    console.warn = (...args: unknown[]) => {
      warnings.push(args.join(' '))
    }
    try {
      sendClipboardWriteOverDc(ch, text)
    } finally {
      console.warn = originalWarn
    }
    expect(warnings.some((w) => w.includes('truncated'))).toBe(true)
    const envelopes = sent.map((s) => JSON.parse(s))
    const totalBytes = envelopes
      .map((e) => new TextEncoder().encode(e.text as string).byteLength)
      .reduce((a, b) => a + b, 0)
    expect(totalBytes).toBeLessThanOrEqual(CLIPBOARD_MAX_BYTES)
  })

  it('every chunked envelope JSON string stays under 16 KB (SCTP ceiling proxy)', () => {
    const { ch, sent } = makeStubDc()
    // Mix of multi-byte chars to verify envelope overhead + UTF-8
    // expansion stays within the budget on a realistic input.
    const text = ('🦀'.repeat(2000) + 'ASCII filler '.repeat(2000) + '中文测试 '.repeat(1000))
    sendClipboardWriteOverDc(ch, text)
    const enc = new TextEncoder()
    for (const s of sent) {
      // The agent's webrtc-rs SCTP has max_message_size=65536; we
      // budget aggressively under that for headroom.
      expect(enc.encode(s).byteLength).toBeLessThan(16 * 1024)
    }
  })
})

describe('normalizeClipboardText (clipboard v2)', () => {
  it('converts CRLF and lone CR to LF', () => {
    expect(normalizeClipboardText('a\r\nb\r\nc')).toBe('a\nb\nc')
    expect(normalizeClipboardText('a\rb')).toBe('a\nb')
    expect(normalizeClipboardText('mixed\r\nand\rand\nend\r')).toBe('mixed\nand\nand\nend\n')
  })

  it('passes through CR-free text untouched', () => {
    expect(normalizeClipboardText('plain\ntext')).toBe('plain\ntext')
    expect(normalizeClipboardText('')).toBe('')
  })
})

describe('the clipboard follows the grant (FR-52 P4e)', () => {
  it('reads CLIPBOARD out of the effective grant, by equality', () => {
    expect(grantAllowsClipboard('VIEW | INPUT | CLIPBOARD | FILES')).toBe(true)
    expect(grantAllowsClipboard('VIEW|CLIPBOARD')).toBe(true)
    // An outsider's default — the case that made this matter.
    expect(grantAllowsClipboard('VIEW | INPUT')).toBe(false)
    expect(grantAllowsClipboard('VIEW')).toBe(false)
    expect(grantAllowsClipboard('')).toBe(false)
    // A newer bit that merely contains the name is not CLIPBOARD.
    expect(grantAllowsClipboard('VIEW | CLIPBOARD_HISTORY')).toBe(false)
  })

  it('a grant the server did not report is the request, which asks for CLIPBOARD', () => {
    expect(grantAllowsClipboard(undefined)).toBe(true)
    expect(grantAllowsClipboard(null)).toBe(true)
  })

  it('drops the clipboard channel — closed and forgotten, so nothing can find it open', () => {
    let closed = 0
    const clipboard = {
      close: () => {
        closed += 1
      },
    } as unknown as RTCDataChannel
    const input = {} as RTCDataChannel
    const channels: Record<string, RTCDataChannel> = { clipboard, input }
    expect(dropClipboardChannel(channels)).toBe(true)
    expect(closed).toBe(1)
    expect(channels.clipboard).toBeUndefined()
    // Only the clipboard: input, control, cursor and files are untouched.
    expect(channels.input).toBe(input)
    // Idempotent: a second create (the #1045 echo) finds nothing to drop.
    expect(dropClipboardChannel(channels)).toBe(false)
    expect(closed).toBe(1)
  })

  it('a channel that throws on close is still forgotten', () => {
    const channels: Record<string, RTCDataChannel> = {
      clipboard: {
        close: () => {
          throw new Error('InvalidStateError')
        },
      } as unknown as RTCDataChannel,
    }
    expect(dropClipboardChannel(channels)).toBe(true)
    expect(channels.clipboard).toBeUndefined()
  })
})

describe('clipboard FNV-1a 64 hashes (clipboard v2)', () => {
  it('matches the published FNV-1a 64 vectors the agent locks too', () => {
    // Same vectors as clipboard::tests::fnv1a64_matches_published_vectors
    // in agents/meshharbord/src/clipboard.rs — echo suppression
    // silently breaks if either side drifts.
    expect(hashClipboardBytes(new Uint8Array(0))).toBe('cbf29ce484222325')
    expect(hashClipboardBytes(new TextEncoder().encode('a'))).toBe('af63dc4c8601ec8c')
    expect(hashClipboardBytes(new TextEncoder().encode('foobar'))).toBe('85944171f73967e8')
  })

  it('hashClipboardText canonicalizes before hashing (CRLF == LF)', () => {
    expect(hashClipboardText('l1\r\nl2')).toBe(hashClipboardText('l1\nl2'))
    expect(hashClipboardText('l1\rl2')).toBe(hashClipboardText('l1\nl2'))
    expect(hashClipboardText('l1\nl2')).not.toBe(hashClipboardText('l1l2'))
  })
})

describe('createClipboardEchoGate (clipboard v2)', () => {
  it('suppresses re-pushing applied and pushed content', () => {
    const gate = createClipboardEchoGate()
    const h1 = hashClipboardText('from remote')
    const h2 = hashClipboardText('from local')
    expect(gate.shouldPush(h1)).toBe(true)
    gate.recordApplied(h1)
    expect(gate.shouldPush(h1)).toBe(false)
    expect(gate.knows(h1)).toBe(true)
    gate.recordPushed(h2)
    expect(gate.shouldPush(h2)).toBe(false)
    expect(gate.knows(h2)).toBe(true)
    // Fresh content still passes.
    expect(gate.shouldPush(hashClipboardText('brand new'))).toBe(true)
  })

  it('never pushes the empty hash and resets cleanly', () => {
    const gate = createClipboardEchoGate()
    expect(gate.shouldPush('')).toBe(false)
    expect(gate.knows('')).toBe(false)
    const h = hashClipboardText('x')
    gate.recordApplied(h)
    gate.reset()
    expect(gate.knows(h)).toBe(false)
    expect(gate.shouldPush(h)).toBe(true)
  })

  it('remembers several hashes per side (v2.1 — html combined + text alt)', () => {
    // One html clipboard state surfaces as TWO hashes: the combined
    // html+text hash (rich reads) and the text-alt hash (readText
    // polling). Both must stay suppressed or the poll re-pushes the
    // alt forever.
    const gate = createClipboardEchoGate()
    const combined = hashClipboardHtml('<b>x</b>', 'x')
    const alt = hashClipboardText('x')
    gate.recordPushed(combined)
    gate.recordPushed(alt)
    expect(gate.shouldPush(combined)).toBe(false)
    expect(gate.shouldPush(alt)).toBe(false)
    // A third and fourth hash don't evict the first two (ring of 4).
    gate.recordPushed(hashClipboardText('y'))
    gate.recordPushed(hashClipboardText('z'))
    expect(gate.knows(combined)).toBe(true)
    expect(gate.knows(alt)).toBe(true)
  })
})

describe('clipboard html helpers (v2.1)', () => {
  it('hashClipboardHtml separates halves and canonicalizes only the text', () => {
    expect(hashClipboardHtml('ab', 'c')).not.toBe(hashClipboardHtml('a', 'bc'))
    expect(hashClipboardHtml('<p>x</p>', 'l1\r\nl2')).toBe(hashClipboardHtml('<p>x</p>', 'l1\nl2'))
    expect(hashClipboardHtml('<p>x</p>', 't')).not.toBe(hashClipboardHtml('<p>y</p>', 't'))
  })

  it('buildClipboardHtmlFrames frames html-then-text with declared byte lengths', () => {
    const html = '<b>bold ümlaut</b>'
    const text = 'bold ümlaut'
    const built = buildClipboardHtmlFrames(html, text)
    expect(built).not.toBeNull()
    const enc = new TextEncoder()
    const begin = JSON.parse(built!.begin)
    expect(begin).toEqual({
      t: 'clipboard:html-begin',
      id: built!.id,
      html_bytes: enc.encode(html).length,
      text_bytes: enc.encode(text).length,
    })
    expect(JSON.parse(built!.end)).toEqual({ t: 'clipboard:html-end', id: built!.id })
    // Frame bytes reassemble to html-bytes ++ text-bytes.
    const total = built!.frames.reduce((a, f) => a + f.byteLength, 0)
    expect(total).toBe(enc.encode(html).length + enc.encode(text).length)
    for (const f of built!.frames) {
      expect(f.byteLength).toBeLessThanOrEqual(CLIPBOARD_IMG_FRAME_BYTES)
    }
    const joined = new Uint8Array(total)
    let off = 0
    for (const f of built!.frames) {
      joined.set(f, off)
      off += f.byteLength
    }
    const dec = new TextDecoder('utf-8')
    expect(dec.decode(joined.subarray(0, enc.encode(html).length))).toBe(html)
    expect(dec.decode(joined.subarray(enc.encode(html).length))).toBe(text)
  })

  it('refuses empty html and oversized payloads', () => {
    expect(buildClipboardHtmlFrames('', 'text')).toBeNull()
    const big = 'x'.repeat(CLIPBOARD_HTML_MAX_BYTES + 1)
    expect(buildClipboardHtmlFrames(big, '')).toBeNull()
  })

  it('splits large html across multiple frames', () => {
    const html = '<i>' + 'a'.repeat(CLIPBOARD_IMG_FRAME_BYTES * 2) + '</i>'
    const built = buildClipboardHtmlFrames(html, 'alt')
    expect(built).not.toBeNull()
    expect(built!.frames.length).toBeGreaterThanOrEqual(3)
  })
})

describe('clipboard native (RTF) helpers (v2.2)', () => {
  it('bytesToBase64 round-trips through base64ToBytes incl. high bytes', () => {
    const bytes = new Uint8Array([0x7b, 0x5c, 0x72, 0x74, 0x66, 0x00, 0xff, 0x80])
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes)
    // Chunk-boundary correctness: > 0x8000 bytes.
    const big = new Uint8Array(0x8000 + 123)
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff
    expect(base64ToBytes(bytesToBase64(big))).toEqual(big)
  })

  it('parseNativeClipPayload validates and decodes base64 rtf', () => {
    const p = parseNativeClipPayload({ rtf: bytesToBase64(new Uint8Array([1, 2, 3])), html: '<b>x</b>', text: 'x' })
    expect(p).not.toBeNull()
    expect(Array.from(p!.rtf)).toEqual([1, 2, 3])
    expect(p!.html).toBe('<b>x</b>')
    expect(p!.text).toBe('x')
    // Missing / empty / non-object rtf → null; html+text default to ''.
    expect(parseNativeClipPayload({ html: 'x' })).toBeNull()
    expect(parseNativeClipPayload({ rtf: '' })).toBeNull()
    expect(parseNativeClipPayload(null)).toBeNull()
    const sparse = parseNativeClipPayload({ rtf: bytesToBase64(new Uint8Array([9])) })
    expect(sparse).not.toBeNull()
    expect(sparse!.html).toBe('')
    expect(sparse!.text).toBe('')
  })

  it('buildClipboardNativeFrames frames rtf++html++text at declared lengths', () => {
    const rtf = new Uint8Array([0x7b, 0x5c, 0x72, 0x74, 0x66, 0x31]) // {\rtf1
    const html = '<b>b</b>'
    const text = 'b'
    const built = buildClipboardNativeFrames(rtf, html, text)
    expect(built).not.toBeNull()
    const enc = new TextEncoder()
    const begin = JSON.parse(built!.begin)
    expect(begin).toEqual({
      t: 'clipboard:native-begin',
      id: built!.id,
      rtf_bytes: rtf.length,
      html_bytes: enc.encode(html).length,
      text_bytes: enc.encode(text).length,
    })
    expect(JSON.parse(built!.end)).toEqual({ t: 'clipboard:native-end', id: built!.id })
    const total = built!.frames.reduce((a, f) => a + f.byteLength, 0)
    expect(total).toBe(rtf.length + enc.encode(html).length + enc.encode(text).length)
    const joined = new Uint8Array(total)
    let off = 0
    for (const f of built!.frames) {
      joined.set(f, off)
      off += f.byteLength
    }
    expect(Array.from(joined.subarray(0, rtf.length))).toEqual(Array.from(rtf))
    const dec = new TextDecoder('utf-8')
    expect(dec.decode(joined.subarray(rtf.length, rtf.length + enc.encode(html).length))).toBe(html)
    expect(dec.decode(joined.subarray(rtf.length + enc.encode(html).length))).toBe(text)
  })

  it('refuses empty rtf and oversized native payloads', () => {
    expect(buildClipboardNativeFrames(new Uint8Array(0), '<b/>', 't')).toBeNull()
    const big = new Uint8Array(CLIPBOARD_NATIVE_MAX_BYTES + 1)
    big[0] = 1
    expect(buildClipboardNativeFrames(big, '', '')).toBeNull()
  })
})

describe('buildClipboardImageFrames (clipboard v2)', () => {
  it('frames a PNG into begin / ≤16KiB binary chunks / end sharing one id', () => {
    const png = new Uint8Array(CLIPBOARD_IMG_FRAME_BYTES * 2 + 123)
    for (let i = 0; i < png.length; i++) png[i] = i & 0xff
    const { id, begin, frames, end } = buildClipboardImageFrames(png, 640, 480)
    expect(frames.length).toBe(3)
    for (const f of frames) {
      expect(f.byteLength).toBeLessThanOrEqual(CLIPBOARD_IMG_FRAME_BYTES)
    }
    // Byte-total + content preserved across frames.
    const total = frames.reduce((a, f) => a + f.byteLength, 0)
    expect(total).toBe(png.length)
    const joined = new Uint8Array(total)
    let off = 0
    for (const f of frames) {
      joined.set(f, off)
      off += f.byteLength
    }
    expect(joined).toEqual(png)
    // Wire shapes the agent's ClipboardIncoming parses.
    const b = JSON.parse(begin)
    expect(b).toEqual({
      t: 'clipboard:img-begin',
      id,
      w: 640,
      h: 480,
      bytes: png.length,
      format: 'png',
    })
    const e = JSON.parse(end)
    expect(e).toEqual({ t: 'clipboard:img-end', id })
  })

  it('single-frame image below the frame size', () => {
    const png = new Uint8Array(100)
    const { frames } = buildClipboardImageFrames(png, 2, 2)
    expect(frames.length).toBe(1)
    expect(frames[0].byteLength).toBe(100)
  })

  it('image byte cap constant matches the agent side', () => {
    expect(CLIPBOARD_IMAGE_MAX_BYTES).toBe(8 * 1024 * 1024)
  })
})

describe('VP9_444_DC_LABEL + videoDcOptions', () => {
  // The agent's `on_data_channel` arm matches on `"video-bytes"`
  // exactly (see agents/meshharbord/src/peer.rs:494). A typo on
  // either side silently turns the entire VP9-444 path into a
  // log-only dead end, so lock the value here.
  it('uses the exact label the agent matches on', () => {
    expect(VP9_444_DC_LABEL).toBe('video-bytes')
  })

  // FR-17 stage B. The historical profile stays the default: reliable +
  // ordered, because without framing SCTP's arrival order IS the
  // reassembly and nothing else can recover it.
  it('defaults to the reliable + ordered profile', () => {
    expect(videoDcOptions(false, false)).toEqual({ ordered: true })
    expect(videoDcOptions(true, false)).toEqual({ ordered: true })
  })

  // ⚠️ The invariant this function exists for. An unframed stream
  // delivered out of order is not a degraded picture — it is garbage the
  // decoder reports as corruption, because a bare byte stream has no way
  // to tell "rest of this frame" from "start of the next". Asking for
  // unordered without framing must therefore be REFUSED, not honoured.
  it('refuses to go unordered without framing', () => {
    expect(videoDcOptions(false, true)).toEqual({ ordered: true })
  })

  it('goes unordered with no retransmits once framing is negotiated', () => {
    // maxRetransmits: 0 is coupled to stage A's assembler, which treats a
    // chunk-index jump as unrecoverable. A retransmitted chunk arriving
    // an RTT late would be discarded as a gap — so 1-2 retransmits
    // (stage C) needs a reorder buffer first and is NOT a number that
    // can be turned up on its own.
    expect(videoDcOptions(true, true)).toEqual({ ordered: false, maxRetransmits: 0 })
  })
})

describe('FR-17 stage B opt-in', () => {
  beforeEach(() => {
    globalThis.localStorage?.clear()
  })

  it('is off unless explicitly enabled', () => {
    expect(storedUnorderedVideo()).toBe(false)
    globalThis.localStorage?.setItem('meshharbor-rc-unordered-video', '0')
    expect(storedUnorderedVideo()).toBe(false)
    globalThis.localStorage?.setItem('meshharbor-rc-unordered-video', 'true')
    expect(storedUnorderedVideo()).toBe(false)
  })

  it('turns on for exactly the documented value', () => {
    globalThis.localStorage?.setItem('meshharbor-rc-unordered-video', '1')
    expect(storedUnorderedVideo()).toBe(true)
  })
})

describe('audio opt-in (persist + request wire shape)', () => {
  beforeEach(() => {
    globalThis.localStorage?.clear()
  })

  it('defaults OFF when nothing is stored', () => {
    expect(readStoredAudioEnabled()).toBe(false)
  })

  it('round-trips through persistAudioEnabled', () => {
    persistAudioEnabled(true)
    expect(readStoredAudioEnabled()).toBe(true)
    persistAudioEnabled(false)
    expect(readStoredAudioEnabled()).toBe(false)
  })

  it('treats any non-"1" stored value as OFF (only the exact flag is truthy)', () => {
    globalThis.localStorage?.setItem('meshharbor-rc-audio-enabled', 'true')
    expect(readStoredAudioEnabled()).toBe(false)
  })

  // The agent's `rc:session.request` handler reads `audio_enabled`
  // (bool) with `#[serde(default)]` — omitting it must mean "no audio".
  // Lock the EXACT field name + presence so a rename on either side is
  // caught here rather than surfacing as silent no-audio in the field.
  it('emits { audio_enabled: true } only when enabled', () => {
    expect(audioRequestFields(true)).toEqual({ audio_enabled: true })
  })

  it('emits an empty object (field omitted) when disabled', () => {
    expect(audioRequestFields(false)).toEqual({})
  })
})

describe('shortCodecFromReceiver', () => {
  function makeReceiver(mime: string | undefined): Pick<RTCRtpReceiver, 'getParameters'> {
    return {
      getParameters: () => ({
        codecs: mime === undefined ? [] : [{ mimeType: mime }],
      } as unknown as RTCRtpSendParameters),
    }
  }

  it('returns h264 when the receiver is null or has no negotiated codec', () => {
    expect(shortCodecFromReceiver(null)).toBe('h264')
    expect(shortCodecFromReceiver(undefined)).toBe('h264')
    expect(shortCodecFromReceiver(makeReceiver(undefined))).toBe('h264')
  })

  it('maps common mime types to their short names', () => {
    expect(shortCodecFromReceiver(makeReceiver('video/H264'))).toBe('h264')
    expect(shortCodecFromReceiver(makeReceiver('video/H265'))).toBe('h265')
    expect(shortCodecFromReceiver(makeReceiver('video/hevc'))).toBe('h265')
    expect(shortCodecFromReceiver(makeReceiver('video/AV1'))).toBe('av1')
    expect(shortCodecFromReceiver(makeReceiver('video/VP9'))).toBe('vp9')
    expect(shortCodecFromReceiver(makeReceiver('video/VP8'))).toBe('vp8')
  })

  it('defaults to h264 when the mime is unrecognised', () => {
    expect(shortCodecFromReceiver(makeReceiver('video/random-codec'))).toBe('h264')
  })
})

describe('codecFromSdp', () => {
  const hevcAnswer = [
    'v=0',
    'o=- 1234 1 IN IP4 127.0.0.1',
    's=-',
    't=0 0',
    'a=group:BUNDLE 0',
    'm=video 9 UDP/TLS/RTP/SAVPF 101 96',
    'c=IN IP4 0.0.0.0',
    'a=rtpmap:101 H265/90000',
    'a=fmtp:101 profile-id=1',
    'a=rtpmap:96 H264/90000',
    'a=sendonly',
  ].join('\r\n')

  const h264Answer = [
    'v=0',
    'm=video 9 UDP/TLS/RTP/SAVPF 96 101',
    'a=rtpmap:96 H264/90000',
    'a=rtpmap:101 H265/90000',
  ].join('\n')

  it('picks the codec matching the first PT on the video m-line', () => {
    // HEVC answer — first PT on m=video is 101 → H265.
    expect(codecFromSdp(hevcAnswer)).toBe('h265')
    // H.264 answer — first PT is 96 → H264.
    expect(codecFromSdp(h264Answer)).toBe('h264')
  })

  it('handles LF-only line endings (some SDP mungers strip CRs)', () => {
    expect(codecFromSdp(h264Answer)).toBe('h264')
  })

  it('recognises the common short names', () => {
    const sdp = (codec: string) =>
      `m=video 9 UDP/TLS/RTP/SAVPF 101\r\na=rtpmap:101 ${codec}/90000\r\n`
    expect(codecFromSdp(sdp('H264'))).toBe('h264')
    expect(codecFromSdp(sdp('H265'))).toBe('h265')
    expect(codecFromSdp(sdp('HEVC'))).toBe('h265')
    expect(codecFromSdp(sdp('AV1'))).toBe('av1')
    expect(codecFromSdp(sdp('VP9'))).toBe('vp9')
    expect(codecFromSdp(sdp('VP8'))).toBe('vp8')
  })

  it('returns null when no video m-line is present', () => {
    expect(codecFromSdp('v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n')).toBeNull()
  })

  it('returns null when the matching rtpmap is missing', () => {
    expect(codecFromSdp('m=video 9 UDP/TLS/RTP/SAVPF 101\r\n')).toBeNull()
  })

  it('returns null for null/undefined/empty input', () => {
    expect(codecFromSdp(null)).toBeNull()
    expect(codecFromSdp(undefined)).toBeNull()
    expect(codecFromSdp('')).toBeNull()
  })

  it('returns null for an unknown codec short name', () => {
    expect(codecFromSdp('m=video 9 X 101\r\na=rtpmap:101 WEIRD/90000\r\n')).toBeNull()
  })
})

describe('rc-vp9-444-worker frame header', () => {
  // Lock the wire format so any change to the agent-side encoder
  // emit gets caught here. Schema: u32 size LE + u8 flags + u64 ts LE.

  function buildHeader(size: number, flags: number, ts: bigint): Uint8Array {
    const buf = new Uint8Array(13)
    const view = new DataView(buf.buffer)
    view.setUint32(0, size, true)
    view.setUint8(4, flags)
    view.setUint32(5, Number(ts & 0xffffffffn), true)
    view.setUint32(9, Number(ts >> 32n), true)
    return buf
  }

  it('parses size + flags + timestamp from a 13-byte header', () => {
    const header = buildHeader(1234, 0x01, 1_700_000_000_000_000n)
    const parsed = parseFrameHeader(header)
    expect(parsed).not.toBeNull()
    expect(parsed!.payloadSize).toBe(1234)
    expect(parsed!.flags).toBe(0x01)
    expect(parsed!.timestampUs).toBe(1_700_000_000_000_000n)
  })

  it('returns null when the input is shorter than the 13-byte header', () => {
    expect(parseFrameHeader(new Uint8Array(0))).toBeNull()
    expect(parseFrameHeader(new Uint8Array(12))).toBeNull()
  })

  it('decodes the keyframe flag bit', () => {
    expect(isKeyframe(0x00)).toBe(false)
    expect(isKeyframe(0x01)).toBe(true)
    // Higher bits reserved — keyframe bit is bit 0 only.
    expect(isKeyframe(0x02)).toBe(false)
    expect(isKeyframe(0x03)).toBe(true)
  })

  it('handles a zero-payload header without throwing', () => {
    const header = buildHeader(0, 0x00, 0n)
    const parsed = parseFrameHeader(header)
    expect(parsed).not.toBeNull()
    expect(parsed!.payloadSize).toBe(0)
  })

  it('round-trips a maximum-realistic 4K-keyframe size', () => {
    // 4K I444 worst-case keyframe is ~6 MB; spec allows up to 16 MB
    // before the worker rejects. Verify the parser doesn't choke at
    // that scale.
    const header = buildHeader(8_000_000, 0x01, 0n)
    const parsed = parseFrameHeader(header)
    expect(parsed!.payloadSize).toBe(8_000_000)
  })
})

describe('leading-delta keyframe gate (rc.103)', () => {
  // Locks the fix for the WINHOST-G hevc_qsv failure: the HW decoder
  // throws "A key frame is required after configure() or flush()" on a
  // leading delta, and the FFmpeg async encoder can ship a buffered delta
  // ahead of the DC-open IDR. The worker must DROP deltas until the first
  // keyframe, then decode everything.
  for (const [label, gate] of [
    ['vp9-444', shouldDecodeFrame],
    ['hevc', shouldDecodeFrameHevc],
  ] as const) {
    describe(label, () => {
      it('drops a leading delta before any keyframe is seen', () => {
        expect(gate(false, false)).toBe(false)
      })

      it('always accepts a keyframe (the resync/start point)', () => {
        expect(gate(false, true)).toBe(true)
      })

      it('accepts deltas once a keyframe has been seen', () => {
        expect(gate(true, false)).toBe(true)
      })

      it('keeps accepting keyframes mid-stream', () => {
        expect(gate(true, true)).toBe(true)
      })

      it('models the DC-open race: drop deltas, latch on the IDR, then flow', () => {
        // Stream the worker would assemble right after "DC opened" on an
        // async encoder: a few buffered deltas, then the forced IDR, then
        // normal GOP. The gate state flips on the first keyframe.
        const stream = [false, false, false, true, false, false, true, false]
        let seen = false
        const decoded: boolean[] = []
        for (const isKey of stream) {
          const accept = gate(seen, isKey)
          decoded.push(accept)
          if (accept && isKey) seen = true
        }
        // First three leading deltas dropped; everything from the IDR on decodes.
        expect(decoded).toEqual([false, false, false, true, true, true, true, true])
      })
    })
  }
})

describe('classifyCrop — HEVC conformance-window handling', () => {
  // Locks the WINHOST-F fix: QSV codes a 1920×1080 desktop as
  // 1920×1088 + an 8-row bottom crop (alignment padding = per-frame junk).
  // The NVDEC-bug rewrap (rc.102) must NOT override that legit crop — doing
  // so painted the junk rows as a purple/blue band flickering during drags.
  const rect = (width: number, height: number, x = 0, y = 0) => ({ x, y, width, height })

  it('trusts the QSV 1080p alignment crop (coded 1088 → visible 1080)', () => {
    expect(classifyCrop(1920, 1088, rect(1920, 1080))).toBe('alignment')
  })

  it('still rewraps the NVDEC misreported-geometry bug (2560×1600 → 1280×720)', () => {
    expect(classifyCrop(2560, 1600, rect(1280, 720))).toBe('spurious')
  })

  it('reports exact when visibleRect equals the coded size', () => {
    expect(classifyCrop(1920, 1200, rect(1920, 1200))).toBe('exact')
  })

  it('reports exact when geometry is missing (closed/exotic frames)', () => {
    expect(classifyCrop(0, 0, rect(1920, 1080))).toBe('exact')
    expect(classifyCrop(1920, 1080, null)).toBe('exact')
  })

  it('treats an offset-origin crop as spurious (alignment crops anchor at 0,0)', () => {
    expect(classifyCrop(1920, 1088, rect(1912, 1080, 8, 0))).toBe('spurious')
  })

  it('draws the alignment boundary at one CTU (64px)', () => {
    // 63 = largest possible alignment pad (dim ≡ 1 mod 64); a ≥64 deficit
    // can only be a genuinely smaller picture → NVDEC-bug territory.
    expect(classifyCrop(1920, 1088, rect(1920, 1025))).toBe('alignment')
    expect(classifyCrop(1920, 1088, rect(1920, 1024))).toBe('spurious')
    expect(classifyCrop(1920, 1088, rect(1856, 1080))).toBe('spurious')
  })

  it('requires BOTH axes inside the alignment band', () => {
    expect(classifyCrop(2560, 1600, rect(2560, 720))).toBe('spurious')
  })

  it('treats a visible rect LARGER than coded as spurious (defensive rewrap)', () => {
    expect(classifyCrop(1920, 1080, rect(1920, 1088))).toBe('spurious')
  })
})

describe('RC_RECONNECT_LADDER_MS', () => {
  it('starts at 250 ms so a desktop transition is barely visible', () => {
    // The first retry must fire fast: a Win+L lock or M3 SYSTEM-
    // context capture handoff resolves in under a second, and a
    // 2 s first delay would leave a visible black-frame window
    // every time. Locking the first entry against accidental
    // "make it slower to be polite to the server" tweaks.
    expect(RC_RECONNECT_LADDER_MS[0]).toBe(250)
  })

  it('ends at 8 s for a real network drop', () => {
    expect(RC_RECONNECT_LADDER_MS[RC_RECONNECT_LADDER_MS.length - 1]).toBe(8000)
  })

  it('caps at 6 attempts so the operator sees a real failure within ~16 s', () => {
    expect(RC_RECONNECT_LADDER_MS.length).toBe(6)
    // Sum the ladder. Worst case (every attempt fails on its
    // delay tick) operator sees error after this many ms.
    const sum = RC_RECONNECT_LADDER_MS.reduce((a, b) => a + b, 0)
    expect(sum).toBeLessThanOrEqual(20_000)
  })

  it('is monotonically non-decreasing', () => {
    for (let i = 1; i < RC_RECONNECT_LADDER_MS.length; i++) {
      expect(RC_RECONNECT_LADDER_MS[i]).toBeGreaterThanOrEqual(
        RC_RECONNECT_LADDER_MS[i - 1],
      )
    }
  })
})

describe('parseControlInbound', () => {
  it('FR-92: parses rc:keep-busy.state, and drops a malformed one', () => {
    const r = parseControlInbound(
      JSON.stringify({
        t: 'rc:keep-busy.state',
        rev: 3,
        available: true,
        on: true,
        phase: 'running',
        pattern: 'star',
        size: 's',
        speed: 'fast',
        resume_after_s: 10,
        warn: [],
      }),
    )
    expect(r?.kind).toBe('keep_busy')
    if (r?.kind === 'keep_busy') {
      expect(r.state.on).toBe(true)
      expect(r.state.pattern).toBe('star')
      expect(r.state.resumeAfterS).toBe(10)
    }
    expect(parseControlInbound('{"t":"rc:keep-busy.state","on":"maybe"}')).toBeNull()
  })

  it('FR-97 P3c-1: parses rc:audio-unavailable and keeps a code it does not know', () => {
    // The agent's payload, as `audio_unavailable_payload` builds it.
    const r = parseControlInbound(
      JSON.stringify({
        t: 'rc:audio-unavailable',
        code: 'no_monitor',
        detail: 'devices: pipewire, pulse, default',
        hint: 'This host sends no sound.',
      }),
    )
    expect(r).toEqual({
      kind: 'audio_unavailable',
      reason: {
        code: 'no_monitor',
        detail: 'devices: pipewire, pulse, default',
        hint: 'This host sends no sound.',
      },
    })
    // Not the video notice: a viewer must not read "no pixels" from it.
    expect(r?.kind).not.toBe('media_unavailable')
    const newer = parseControlInbound('{"t":"rc:audio-unavailable","code":"from_a_newer_agent"}')
    expect(newer).toEqual({
      kind: 'audio_unavailable',
      reason: { code: 'from_a_newer_agent', detail: '', hint: '' },
    })
    expect(parseControlInbound('{"t":"rc:audio-unavailable"}')).toBeNull()
  })

  it('parses rc:clock.echo (FR-1 P7) and rejects non-numeric fields', () => {
    const r = parseControlInbound('{"t":"rc:clock.echo","t0":1500,"agent_us":5000}')
    expect(r).toEqual({ kind: 'clock_echo', t0: 1500, agentUs: 5000 })
    // A t0 the agent echoed from a hostile/odd probe must not parse.
    expect(parseControlInbound('{"t":"rc:clock.echo","t0":"x","agent_us":5}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:clock.echo","t0":null,"agent_us":5}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:clock.echo","t0":1500}')).toBeNull()
  })

  it('parses a well-formed rc:host_locked locked=true', () => {
    const r = parseControlInbound('{"t":"rc:host_locked","locked":true}')
    expect(r).toEqual({ kind: 'host_locked', locked: true, input: 'suppressed' })
  })

  it('parses a well-formed rc:host_locked locked=false', () => {
    const r = parseControlInbound('{"t":"rc:host_locked","locked":false}')
    expect(r).toEqual({ kind: 'host_locked', locked: false, input: 'suppressed' })
  })

  it('FR-97 P3b: a Linux lock hint says the lock screen takes input', () => {
    // The agent's payload (`host_locked_advisory_payload`, peer.rs).
    const r = parseControlInbound('{"t":"rc:host_locked","locked":true,"input":"passes"}')
    expect(r).toEqual({ kind: 'host_locked', locked: true, input: 'passes' })
    // Only the known words count: anything else is Windows' meaning.
    const other = parseControlInbound('{"t":"rc:host_locked","locked":true,"input":"suppressed"}')
    expect(other).toEqual({ kind: 'host_locked', locked: true, input: 'suppressed' })
    const odd = parseControlInbound('{"t":"rc:host_locked","locked":true,"input":"blocked"}')
    expect(odd).toEqual({ kind: 'host_locked', locked: true, input: 'suppressed' })
  })

  it('FR-97 P2d-1: a Mac lock hint claims neither way about input', () => {
    // `lock_state::LOCK_SCREEN_INPUT` on a Mac.
    const r = parseControlInbound('{"t":"rc:host_locked","locked":true,"input":"unknown"}')
    expect(r).toEqual({ kind: 'host_locked', locked: true, input: 'unknown' })
  })

  it('FR-97 P2d-1: the Host locked chip says only what the host said', () => {
    expect(hostLockedChipTitle('passes')).toMatch(/type the password to unlock/)
    expect(hostLockedChipTitle('suppressed')).toMatch(/input is suppressed/)
    const unknown = hostLockedChipTitle('unknown')
    expect(unknown).toBe('The remote host is on its lock screen.')
    expect(unknown).not.toMatch(/input/i)
  })

  // FR-93 P1 — the agent's wire shape (input/reach.rs `payload`, locked there).
  it('parses rc:input-reach, keeping an unknown reach and a missing reason', () => {
    expect(
      parseControlInbound(
        '{"t":"rc:input-reach","reach":"none","reason":"XTest reaches no window at all"}',
      ),
    ).toEqual({
      kind: 'input_reach',
      reach: { reach: 'none', reason: 'XTest reaches no window at all' },
    })
    expect(parseControlInbound('{"t":"rc:input-reach","reach":"some_future_value"}')).toEqual({
      kind: 'input_reach',
      reach: { reach: 'some_future_value', reason: '' },
    })
    expect(parseControlInbound('{"t":"rc:input-reach"}')).toBeNull()
  })

  // FR-101 P4b-2b — the agent's wire shape (session_idle.rs `notice_json`,
  // locked there): a duration in ms, or null to withdraw.
  it('parses rc:idle: a countdown, its withdrawal, and nothing else', () => {
    expect(parseControlInbound('{"t":"rc:idle","ends_in_ms":60000}')).toEqual({
      kind: 'idle',
      endsInMs: 60000,
    })
    expect(parseControlInbound('{"t":"rc:idle","ends_in_ms":null}')).toEqual({
      kind: 'idle',
      endsInMs: null,
    })
    for (const bad of [
      '{"t":"rc:idle"}',
      '{"t":"rc:idle","ends_in_ms":-5}',
      '{"t":"rc:idle","ends_in_ms":"60s"}',
    ]) {
      expect(parseControlInbound(bad), bad).toBeNull()
    }
  })

  it('FR-101 P4b-2b: counts the idle warning down in whole seconds, rounded up, never below zero', () => {
    expect(idleSecondsLeft(null, 1000)).toBeNull()
    expect(idleSecondsLeft(61_000, 1000)).toBe(60)
    expect(idleSecondsLeft(60_500, 1000)).toBe(60)
    expect(idleSecondsLeft(1_001, 1000)).toBe(1)
    expect(idleSecondsLeft(1000, 1000)).toBe(0)
    expect(idleSecondsLeft(500, 1000)).toBe(0)
  })

  // FR-93 P2d-2 — the agent's wire shape (peer.rs `media_waiting_payload`,
  // locked there): a duration in ms, never a time of day.
  it('parses rc:media-waiting, keeping an unknown `for` and a missing hint', () => {
    expect(
      parseControlInbound(
        '{"t":"rc:media-waiting","for":"person_at_screen","waits_ms":117250,"hint":"asked to share"}',
      ),
    ).toEqual({ kind: 'media_waiting', for: 'person_at_screen', waitsMs: 117250, hint: 'asked to share' })
    expect(parseControlInbound('{"t":"rc:media-waiting","for":"some_future_wait","waits_ms":0}')).toEqual({
      kind: 'media_waiting',
      for: 'some_future_wait',
      waitsMs: 0,
      hint: '',
    })
    // No duration, or a nonsense one, is not a wait the watchdog can honour.
    expect(parseControlInbound('{"t":"rc:media-waiting","for":"person_at_screen"}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:media-waiting","for":"person_at_screen","waits_ms":-5}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:media-waiting","for":"person_at_screen","waits_ms":"120000"}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:media-waiting","waits_ms":1000}')).toBeNull()
  })

  it('returns null for non-string input', () => {
    // Real ondatachannel messages can deliver Blob / ArrayBuffer
    // when the sender uses binary mode; our agent always sends
    // text but the type guard must not crash on the alternative.
    expect(parseControlInbound(null)).toBeNull()
    expect(parseControlInbound(123)).toBeNull()
    expect(parseControlInbound(new ArrayBuffer(8))).toBeNull()
  })

  it('returns null for non-JSON strings', () => {
    expect(parseControlInbound('not json')).toBeNull()
    expect(parseControlInbound('')).toBeNull()
    expect(parseControlInbound('{')).toBeNull()
  })

  it('returns null for JSON that is not an object', () => {
    // `JSON.parse` accepts bare values; the wire format requires
    // an envelope object so anything else is a wire-format bug
    // the older agent / future agent might emit.
    expect(parseControlInbound('null')).toBeNull()
    expect(parseControlInbound('42')).toBeNull()
    expect(parseControlInbound('"string"')).toBeNull()
    expect(parseControlInbound('[1,2,3]')).toBeNull()
  })

  it('returns null for unknown envelope types', () => {
    // Future agent versions may emit additional `t` values; older
    // browsers must skip them silently rather than crash.
    expect(parseControlInbound('{"t":"rc:cursor-shape","data":"..."}')).toBeNull()
    expect(parseControlInbound('{"t":"unknown"}')).toBeNull()
    expect(parseControlInbound('{}')).toBeNull()
  })

  it('returns null when locked is not a boolean', () => {
    // Defensive: a malformed agent that sends locked="true" or
    // locked=1 must NOT pass through as truthy. Lock state UI
    // should never be steered by stringly-typed input.
    expect(parseControlInbound('{"t":"rc:host_locked","locked":"true"}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:host_locked","locked":1}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:host_locked"}')).toBeNull()
  })

  it('parses a well-formed rc:desktop_changed', () => {
    // M3 A1 SYSTEM-context worker emits this after every
    // try_change_desktop Switched. Powers the secondary
    // "On Winlogon" chip.
    const r = parseControlInbound('{"t":"rc:desktop_changed","name":"Winlogon"}')
    expect(r).toEqual({ kind: 'desktop_changed', name: 'Winlogon' })
  })

  it('parses rc:desktop_changed with arbitrary desktop name', () => {
    // Default / Winlogon are the common cases but Windows can
    // present screen-saver / custom desktops too. Don't restrict.
    const r = parseControlInbound('{"t":"rc:desktop_changed","name":"Default"}')
    expect(r).toEqual({ kind: 'desktop_changed', name: 'Default' })
    const r2 = parseControlInbound('{"t":"rc:desktop_changed","name":"Screen-saver"}')
    expect(r2).toEqual({ kind: 'desktop_changed', name: 'Screen-saver' })
  })

  it('returns null when desktop_changed name is missing or wrong type', () => {
    // Defensive: stringly-typed numbers / null / missing field all
    // get rejected so we can never set currentDesktop to a
    // non-string runtime value.
    expect(parseControlInbound('{"t":"rc:desktop_changed"}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:desktop_changed","name":42}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:desktop_changed","name":null}')).toBeNull()
  })

  it('returns null when desktop_changed name is empty string', () => {
    // Empty name has no semantic meaning + the viewer would render
    // an empty chip, so reject at the parse layer.
    expect(parseControlInbound('{"t":"rc:desktop_changed","name":""}')).toBeNull()
  })

  // rc.23 — rc:logs-fetch.reply round-trip from the agent's
  // diagnostic log-tail handler. Browser uses this to surface ESET
  // / sync_data failures the operator can't see otherwise.
  it('parses rc:logs-fetch.reply with ok=true and lines array', () => {
    const r = parseControlInbound(
      '{"t":"rc:logs-fetch.reply","ok":true,"path":"C:\\\\Users\\\\me\\\\log","lines":["a","b","c"],"truncated":false}'
    )
    expect(r).toEqual({
      kind: 'logs_fetch_reply',
      reply: {
        ok: true,
        path: 'C:\\Users\\me\\log',
        lines: ['a', 'b', 'c'],
        truncated: false,
      },
    })
  })

  it('parses rc:logs-fetch.reply ok=false with error message', () => {
    // Agent's fetch_tail() failed path (e.g. log file rotated mid-
    // read). Browser surfaces the message in a red caption.
    const r = parseControlInbound(
      // RETIRED-NAME-ANCHOR(6): mirrors the daemon's real message, which names
      // BOTH prefixes because an upgraded host still has pre-rename log files.
      '{"t":"rc:logs-fetch.reply","ok":false,"error":"no meshharbord.log* or meshharbor-agent.log* file"}'
    )
    expect(r).toEqual({
      kind: 'logs_fetch_reply',
      reply: { ok: false, error: 'no meshharbord.log* or meshharbor-agent.log* file' },
    })
  })

  it('rc:logs-fetch.reply filters non-string entries from lines', () => {
    // Defensive: agent contract requires string lines but a future
    // wire-format drift shouldn't crash the browser. Filter to
    // strings before the UI binds.
    const r = parseControlInbound(
      '{"t":"rc:logs-fetch.reply","ok":true,"lines":["good",42,null,"also good"]}'
    )
    expect(r).toEqual({
      kind: 'logs_fetch_reply',
      reply: { ok: true, lines: ['good', 'also good'] },
    })
  })

  it('rc:logs-fetch.reply treats truncated as boolean only', () => {
    // Non-boolean truncated values omit the field entirely; the UI
    // renders without the "more entries omitted" hint rather than
    // showing a stringified value.
    const r = parseControlInbound(
      '{"t":"rc:logs-fetch.reply","ok":true,"truncated":"yes"}'
    )
    expect(r).toEqual({ kind: 'logs_fetch_reply', reply: { ok: true } })
  })
})

// rc.NEXT — remote app selection & launch (virtual-desktop hosts). The
// Apps menu is driven entirely by these pure parsers + wire builders, so
// they carry the wire-format invariants.
describe('parseAppsListReply', () => {
  it('parses a full list reply with windows + launchable', () => {
    const reply = parseAppsListReply({
      t: 'rc:apps.list.reply',
      id: 'a1',
      ok: true,
      supported: true,
      windows: [
        { window_id: '0x1', title: 'Terminal (main)', session: 'main', focused: true },
        { window_id: '0x2', title: 'htop', app_key: 'htop', focused: false },
      ],
      launchable: [{ key: 'bash', label: 'New bash session' }],
    })
    expect(reply.ok).toBe(true)
    expect(reply.supported).toBe(true)
    expect(reply.windows).toEqual([
      { window_id: '0x1', title: 'Terminal (main)', session: 'main', focused: true },
      { window_id: '0x2', title: 'htop', app_key: 'htop', focused: false },
    ])
    expect(reply.launchable).toEqual([{ key: 'bash', label: 'New bash session' }])
  })

  it('defaults ok/supported to false and arrays to empty when missing (version skew)', () => {
    const reply = parseAppsListReply({ t: 'rc:apps.list.reply' })
    expect(reply).toEqual({ ok: false, supported: false, windows: [], launchable: [] })
    // FR-56 P2: an agent older than P2 sends no coverage. Absent must stay
    // absent — inventing an empty one would claim the listing was complete.
    expect(reply.coverage).toBeUndefined()
  })

  it('carries coverage so an empty list is distinguishable from an unenumerable source', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: true,
      windows: [],
      launchable: [],
      coverage: { sources: ['x11'], unlisted: 'native Wayland windows: no protocol' },
    })
    expect(reply.windows).toEqual([])
    expect(reply.coverage?.sources).toEqual(['x11'])
    expect(reply.coverage?.unlisted).toContain('native Wayland')
  })

  it('parses coverage defensively — a malformed one costs the caveat, not the reply', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: true,
      windows: [{ window_id: '0x1', title: 'ok', focused: false }],
      launchable: [],
      coverage: { sources: ['x11', 7, null], unlisted: '' },
    })
    expect(reply.ok).toBe(true)
    expect(reply.windows).toHaveLength(1)
    expect(reply.coverage?.sources).toEqual(['x11'])
    // An empty `unlisted` is not a caveat; it must not render as one.
    expect(reply.coverage?.unlisted).toBeUndefined()
  })

  it('filters malformed window + launchable entries', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: true,
      windows: [
        { window_id: '0x1', title: 'ok', focused: false },
        { window_id: 42, title: 'bad id' },
        { title: 'no id' },
        'not-an-object',
      ],
      launchable: [{ key: 'bash', label: 'Bash' }, { key: 'x' }, { label: 'y' }],
    })
    expect(reply.windows).toEqual([{ window_id: '0x1', title: 'ok', focused: false }])
    expect(reply.launchable).toEqual([{ key: 'bash', label: 'Bash' }])
  })

  it('carries an error string when present and coerces non-boolean focused', () => {
    const reply = parseAppsListReply({
      ok: false,
      supported: true,
      error: 'wmctrl not installed',
      windows: [{ window_id: '0x1', title: 't', focused: 'yes' }],
    })
    expect(reply.error).toBe('wmctrl not installed')
    expect(reply.windows[0].focused).toBe(false)
  })

  // FR-56 AC10. P5 (#1179) added `missing_tools` to the agent, the interface
  // and the template — and not to this parser, so the field the agent sent
  // was dropped between the wire and the screen. This test is RED on that
  // parser (asserted by reverting the parse and running it).
  it('carries missing_tools — the P5 field this parser used to drop (FR-56 AC10)', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: true,
      windows: [],
      launchable: [],
      coverage: {
        sources: ['x11'],
        missing_tools: [
          { tool: 'tmux', blocks: 'persistent shell sessions', install: 'apt install tmux' },
        ],
      },
    })
    expect(reply.coverage?.missing_tools).toEqual([
      { tool: 'tmux', blocks: 'persistent shell sessions', install: 'apt install tmux' },
    ])
  })

  it('drops a malformed missing_tools entry and keeps the rest; absent stays absent', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: true,
      coverage: {
        sources: ['x11'],
        missing_tools: [
          { tool: 'tmux', blocks: 'shell sessions', install: 'apt install tmux' },
          { tool: 'xterm' }, // no blocks / install — unactionable, dropped
          { tool: '', blocks: 'x', install: 'y' }, // nameless, dropped
          'xterm',
          null,
        ],
      },
    })
    expect(reply.coverage?.missing_tools).toEqual([
      { tool: 'tmux', blocks: 'shell sessions', install: 'apt install tmux' },
    ])
    // An agent between P2 and P5 sends coverage with no missing_tools at all.
    // Absent must stay absent — an empty array would claim "checked, none".
    const older = parseAppsListReply({ ok: true, supported: true, coverage: { sources: ['x11'] } })
    expect(older.coverage?.missing_tools).toBeUndefined()
  })

  it('carries the refusal reason beside supported:false (FR-56 AC10)', () => {
    const reply = parseAppsListReply({
      ok: true,
      supported: false,
      windows: [],
      launchable: [],
      unavailable: {
        code: 'no_session',
        reason: 'No active graphical login session on this host — nobody is at its screen.',
      },
    })
    expect(reply.supported).toBe(false)
    expect(reply.unavailable).toEqual({
      code: 'no_session',
      reason: 'No active graphical login session on this host — nobody is at its screen.',
    })
  })

  it('a malformed unavailable costs itself, never the reply — and an absent one stays absent', () => {
    for (const bad of [
      { code: 'no_session' }, // no sentence to show
      { reason: 'words' }, // no code to key off
      { code: '', reason: 'words' },
      { code: 'x', reason: '' },
      'no_session',
      42,
      null,
    ]) {
      const reply = parseAppsListReply({ ok: true, supported: false, unavailable: bad })
      expect(reply.ok).toBe(true)
      expect(reply.supported).toBe(false)
      expect(reply.unavailable, JSON.stringify(bad)).toBeUndefined()
    }
    // Pre-AC10 agents: `supported: false` and nothing beside it.
    expect(parseAppsListReply({ ok: true, supported: false }).unavailable).toBeUndefined()
  })
})

describe('parseAppsActionReply', () => {
  it('carries the refusal reason on a focus/launch refused for want of a backend (FR-56 AC10)', () => {
    expect(
      parseAppsActionReply({
        ok: false,
        error: 'apps not available on this host: Remote apps are disabled on this device',
        unavailable: { code: 'disabled', reason: 'Remote apps are disabled on this device' },
      }),
    ).toEqual({
      ok: false,
      error: 'apps not available on this host: Remote apps are disabled on this device',
      unavailable: { code: 'disabled', reason: 'Remote apps are disabled on this device' },
    })
    expect(parseAppsActionReply({ ok: false, unavailable: { code: 'disabled' } })).toEqual({
      ok: false,
    })
  })

  it('parses focus/launch ok replies with optional window_id', () => {
    expect(parseAppsActionReply({ ok: true })).toEqual({ ok: true })
    expect(parseAppsActionReply({ ok: true, window_id: '0xNEW' })).toEqual({
      ok: true,
      window_id: '0xNEW',
    })
  })

  it('parses error replies and coerces non-boolean ok to false', () => {
    expect(parseAppsActionReply({ ok: false, error: 'no such window' })).toEqual({
      ok: false,
      error: 'no such window',
    })
    expect(parseAppsActionReply({ ok: 'truthy' }).ok).toBe(false)
  })
})

describe('parseControlInbound — rc:apps.*', () => {
  it('routes rc:apps.list.reply with id', () => {
    const r = parseControlInbound(
      '{"t":"rc:apps.list.reply","id":"a1","ok":true,"supported":true,"windows":[],"launchable":[]}'
    )
    expect(r).toEqual({
      kind: 'apps_list_reply',
      id: 'a1',
      reply: { ok: true, supported: true, windows: [], launchable: [] },
    })
  })

  it('tolerates a null / missing id on apps replies', () => {
    const r = parseControlInbound('{"t":"rc:apps.list.reply","ok":true,"supported":false}')
    expect(r?.kind).toBe('apps_list_reply')
    expect((r as { id: string | null }).id).toBeNull()
  })

  it('routes focus + launch replies', () => {
    expect(parseControlInbound('{"t":"rc:apps.focus.reply","id":"f1","ok":true}')).toEqual({
      kind: 'apps_focus_reply',
      id: 'f1',
      reply: { ok: true },
    })
    expect(
      parseControlInbound('{"t":"rc:apps.launch.reply","id":"l1","ok":true,"window_id":"0x9"}')
    ).toEqual({
      kind: 'apps_launch_reply',
      id: 'l1',
      reply: { ok: true, window_id: '0x9' },
    })
  })

  it('returns null for an unknown rc:apps.* subtype (forward-compat)', () => {
    expect(parseControlInbound('{"t":"rc:apps.something-new"}')).toBeNull()
  })
})

describe('apps wire builders', () => {
  it('appsListWireMessage builds { t, id } and rejects empty id', () => {
    expect(appsListWireMessage('a1')).toEqual({ t: 'rc:apps.list', id: 'a1' })
    expect(appsListWireMessage('')).toBeNull()
  })

  it('appsFocusWireMessage requires id + windowId', () => {
    expect(appsFocusWireMessage('a1', '0x5')).toEqual({
      t: 'rc:apps.focus',
      id: 'a1',
      window_id: '0x5',
    })
    expect(appsFocusWireMessage('a1', '')).toBeNull()
    expect(appsFocusWireMessage('', '0x5')).toBeNull()
  })

  it('appsLaunchWireMessage requires id + appKey', () => {
    expect(appsLaunchWireMessage('a1', 'bash')).toEqual({
      t: 'rc:apps.launch',
      id: 'a1',
      app_key: 'bash',
    })
    expect(appsLaunchWireMessage('a1', '')).toBeNull()
    expect(appsLaunchWireMessage('', 'bash')).toBeNull()
  })
})

describe('deadAirDelayMs', () => {
  it('stays out of the way for the first couple of frameless cycles', () => {
    // A lock-screen / SYSTEM-context handoff or a codec renegotiation can
    // legitimately produce one frameless session; those must still recover at
    // ladder speed, so the dead-air floor is zero until the pattern repeats.
    expect(deadAirDelayMs(0)).toBe(0)
    expect(deadAirDelayMs(1)).toBe(0)
    expect(deadAirDelayMs(2)).toBe(0)
  })

  it('backs off to minutes once dead air is clearly the steady state', () => {
    // From the 3rd consecutive frameless session the pair almost certainly has
    // no media path at all (winhost-a: 388 sessions in 24 h, each ~10.9 s of
    // dead air). Retrying every ~19 s buys nothing.
    expect(deadAirDelayMs(3)).toBe(30_000)
    expect(deadAirDelayMs(4)).toBe(60_000)
    expect(deadAirDelayMs(5)).toBe(120_000)
    expect(deadAirDelayMs(6)).toBe(300_000)
  })

  it('caps rather than growing without bound, and never returns a negative', () => {
    expect(deadAirDelayMs(7)).toBe(300_000)
    expect(deadAirDelayMs(10_000)).toBe(300_000)
    expect(deadAirDelayMs(-1)).toBe(0)
  })

  it('dominates the connection ladder exactly when it should', () => {
    // The scheduler takes Math.max of the two. Early on the fast ladder wins
    // (recovery stays quick); once dead air repeats, the floor takes over.
    expect(Math.max(nextReconnectDelayMs(0), deadAirDelayMs(1))).toBe(250)
    expect(Math.max(nextReconnectDelayMs(5), deadAirDelayMs(2))).toBe(8000)
    expect(Math.max(nextReconnectDelayMs(5), deadAirDelayMs(3))).toBe(30_000)
    expect(Math.max(nextReconnectDelayMs(100), deadAirDelayMs(6))).toBe(300_000)
  })
})

describe('nextReconnectDelayMs', () => {
  it('returns the ladder value for valid attempt indices', () => {
    expect(nextReconnectDelayMs(0)).toBe(250)
    expect(nextReconnectDelayMs(1)).toBe(500)
    expect(nextReconnectDelayMs(2)).toBe(1000)
    expect(nextReconnectDelayMs(3)).toBe(2000)
    expect(nextReconnectDelayMs(4)).toBe(4000)
    expect(nextReconnectDelayMs(5)).toBe(8000)
  })

  it('falls back to steady-state delay past the ladder (rc.23: infinite retry)', () => {
    // rc.23 — operators on AV-protected hosts need indefinite retry;
    // returning `null` past the cap surfaced "budget exhausted" in
    // the field. The 7th attempt and beyond return
    // `RC_RECONNECT_STEADY_MS` (8 s) — caller keeps retrying.
    expect(nextReconnectDelayMs(6)).toBe(8000)
    expect(nextReconnectDelayMs(100)).toBe(8000)
    expect(nextReconnectDelayMs(10_000)).toBe(8000)
  })

  it('returns the first-attempt delay on negative input (defensive)', () => {
    // Defensive: a logic bug that decremented the counter past 0
    // shouldn't strand the loop. Returns the first-attempt delay
    // (250 ms) so the loop continues. rc.23 — was `null` pre-change.
    expect(nextReconnectDelayMs(-1)).toBe(250)
  })
})

describe('nextDirPath', () => {
  // Returns null when the entry isn't a directory — the drawer's
  // dbl-click handler short-circuits before navigating.
  it('returns null for non-directory entries', () => {
    expect(
      nextDirPath({ name: 'report.pdf', is_dir: false }, 'C:\\Users', false)
    ).toBeNull()
  })

  describe('roots view', () => {
    // Roots view: drive INTO entry.name directly. Concatenating with
    // a localised "Drives" label produced bogus paths like
    // `Drives/C:\` (rc.15 field repro 2026-05-07). The fix uses an
    // explicit `isRootsView` flag.
    it('Windows drive: dbl-click "C:\\" lands at C:\\, not Drives/C:\\', () => {
      // currentDirPath comes from the agent's roots listing as
      // "Drives" — must be ignored.
      expect(
        nextDirPath({ name: 'C:\\', is_dir: true }, 'Drives', true)
      ).toBe('C:\\')
    })

    it('Unix root: dbl-click "/" lands at /, not //', () => {
      expect(
        nextDirPath({ name: '/', is_dir: true }, '/', true)
      ).toBe('/')
    })
  })

  describe('inside a real directory', () => {
    it('Windows: appends with backslash, no double-up on trailing sep', () => {
      // Trailing separator on the parent (after canonicalize) — must
      // NOT produce `C:\\dev`. This is the literal regression case
      // for `\\?\C:\` whose canonicalised form ends in `\`.
      expect(
        nextDirPath({ name: 'dev', is_dir: true }, '\\\\?\\C:\\', false)
      ).toBe('\\\\?\\C:\\dev')
      // No-trailing-sep parent → adds backslash.
      expect(
        nextDirPath({ name: 'gjovanov', is_dir: true }, 'C:\\dev', false)
      ).toBe('C:\\dev\\gjovanov')
    })

    it('Unix: appends with forward slash, no double-up on trailing sep', () => {
      expect(
        nextDirPath({ name: 'home', is_dir: true }, '/', false)
      ).toBe('/home')
      expect(
        nextDirPath({ name: 'goran', is_dir: true }, '/home', false)
      ).toBe('/home/goran')
    })

    it('detects Windows separator from drive-letter prefix', () => {
      // `C:\Users` → Windows backslash heuristic.
      expect(
        nextDirPath({ name: 'me', is_dir: true }, 'C:\\Users', false)
      ).toBe('C:\\Users\\me')
    })

    it('treats path with no backslashes + no drive letter as Unix', () => {
      expect(
        nextDirPath({ name: 'b', is_dir: true }, '/usr/local', false)
      ).toBe('/usr/local/b')
    })
  })

  describe('regression: \\\\?\\C:\\ → dev', () => {
    // Exact reproduction of the field bug fixed 2026-05-09. The
    // agent canonicalises `C:\` → `\\?\C:\`. `Path::parent()` of
    // `\\?\C:\` returns None, so a `currentParent === null` check
    // mis-classified the verbatim drive root as roots view, and
    // dbl-click `dev` shipped just `"dev"` to the agent —
    // "canonicalising dev". The explicit `isRootsView=false` here
    // is the correct call site signal: the user came in via
    // navigateTo(C:\\), not navigateTo("").
    it('produces the agent-acceptable absolute path \\\\?\\C:\\dev', () => {
      expect(
        nextDirPath({ name: 'dev', is_dir: true }, '\\\\?\\C:\\', false)
      ).toBe('\\\\?\\C:\\dev')
    })
  })
})

describe('pickAutoTransport (rc.190 HW×HW codec auto-rank)', () => {
  const base = (over: Partial<AutoTransportInputs>): AutoTransportInputs => ({
    agentTransports: [],
    agentHwEncoders: [],
    viewerAv1Hw: false,
    viewerHevcHw: false,
    viewerHevcDecodable: false,
    viewerVp9Hw: false,
    viewerVp9Decodable: false,
    viewerH264Hw: false,
    ...over,
  })

  // #2231 — Firefox's WebCodecs decodes VP9 profile 0, not profile 1. Before
  // the profile-0 rung it fell to the RTP track, where an agent offering only
  // H.264 left a Firefox without OpenH264 with no codec in common.
  it('a browser with VP9 profile 0 only and no H.264 takes the VP9 DataChannel at 4:2:0 (#2231)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444'],
        agentHwEncoders: ['libvpx-vp9-444-sw'],
        viewerVp9Decodable: false,
        viewerVp9_420Decodable: true,
        viewerRtpH264: false,
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv420')
  })

  it('profile 0 only never gets 4:4:4, whatever the dial or the dropdown asks (#2231)', () => {
    for (const over of [{ priority: 'sharper' as const }, { chromaPref: 'yuv444' as const }]) {
      const r = pickAutoTransport(
        base({
          agentTransports: ['data-channel-vp9-444'],
          viewerVp9Decodable: false,
          viewerVp9_420Decodable: true,
          viewerRtpH264: false,
          ...over,
        }),
      )
      expect(r.transport).toBe('data-channel-vp9-444')
      expect(r.chromaOverride).toBe('yuv420')
    }
  })

  // A profile-0-only browser that decodes H.264 (Safari, a Firefox with
  // OpenH264) keeps the RTP track it has always used: the rung rescues the
  // broken case and moves no working one.
  it('a profile-0-only browser that decodes H.264 keeps the RTP track (#2231)', () => {
    for (const viewerRtpH264 of [true, undefined]) {
      const r = pickAutoTransport(
        base({
          agentTransports: ['data-channel-vp9-444'],
          viewerVp9Decodable: false,
          viewerVp9_420Decodable: true,
          viewerRtpH264,
        }),
      )
      expect(r.transport).toBeNull()
    }
  })

  it('an absent profile-0 probe changes nothing, and nor does an agent without the VP9 DataChannel (#2231)', () => {
    expect(
      pickAutoTransport(base({ agentTransports: ['data-channel-vp9-444'], viewerRtpH264: false }))
        .transport,
    ).toBeNull()
    expect(
      pickAutoTransport(
        base({ agentTransports: [], viewerVp9_420Decodable: true, viewerRtpH264: false }),
      ).transport,
    ).toBeNull()
  })

  it('a browser that decodes profile 1 keeps its rung: Sharper still means 4:4:4 (#2231)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444'],
        viewerVp9Decodable: true,
        viewerVp9_420Decodable: true,
        priority: 'sharper',
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv444')
  })

  it('DEVBOX→capable-viewer pair picks AV1 (HW on both ends)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-hevc', 'data-channel-av1'],
        agentHwEncoders: ['ffmpeg-hevc_nvenc', 'ffmpeg-av1_nvenc', 'libvpx-vp9-444-sw'],
        viewerAv1Hw: true,
        viewerHevcHw: true,
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).toBe('data-channel-av1')
  })

  it('WINHOST-H→WINHOST-A pair picks HEVC (agent has NO AV1/VP9 HW encode)', () => {
    // UHD 630 + GTX 1650: hevc_nvenc is the only HW DC encoder.
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-hevc'],
        agentHwEncoders: ['ffmpeg-hevc_nvenc', 'libvpx-vp9-444-sw'],
        viewerAv1Hw: true, // viewer could do AV1 — agent can't encode it
        viewerHevcHw: true,
        viewerHevcDecodable: true,
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).toBe('data-channel-hevc')
    expect(r.chromaOverride).toBeNull()
  })

  it('weak viewer (no HW HEVC) on an Intel sender lands on VP9 4:2:0 HW×HW', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-hevc'],
        agentHwEncoders: ['ffmpeg-hevc_qsv', 'ffmpeg-vp9_qsv', 'libvpx-vp9-444-sw'],
        viewerHevcHw: false, // HEVC would be SW-decoded here — skip it
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv420')
  })

  it('no HW×HW pair at all → VP9 SW-encode fallback (agent caps it ≤1920)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444'],
        agentHwEncoders: ['libvpx-vp9-444-sw'],
        viewerVp9Hw: false,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv420')
  })

  // Priority -> chroma. A Mac has no HW encoder at all, so Auto always
  // lands it on the SW rung, where 4:2:0 subsampled exactly the colour
  // edges that make terminal text legible. `sharper` buys full chroma at
  // the cost of SW decode; nothing else changes behaviour.
  it('Sharper upgrades the VP9 SW rung to 4:4:4 (the macOS text case)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444'],
        agentHwEncoders: ['libvpx-vp9-444-sw'],
        viewerVp9Hw: false,
        viewerVp9Decodable: true,
        priority: 'sharper',
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv444')
  })

  it('Sharper does NOT force 4:4:4 onto the vp9_qsv HW rung', () => {
    // libvpx always has profile 1; vp9_qsv's 4:4:4 support is not
    // established, and forcing it could fail the encoder open. The dial
    // must not reach a rung whose encoder might refuse the format.
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444'],
        agentHwEncoders: ['ffmpeg-vp9_qsv', 'libvpx-vp9-444-sw'],
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
        priority: 'sharper',
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
    expect(r.chromaOverride).toBe('yuv420')
  })

  it('balanced / smoother / absent all keep the SW rung on 4:2:0', () => {
    const sw = {
      agentTransports: ['data-channel-vp9-444'],
      agentHwEncoders: ['libvpx-vp9-444-sw'],
      viewerVp9Decodable: true,
    }
    for (const priority of ['balanced', 'smoother', undefined] as const) {
      expect(pickAutoTransport(base({ ...sw, priority })).chromaOverride).toBe('yuv420')
    }
  })

  it('P2 — H.264-DC HW×HW slots ABOVE the VP9 SW-encode tier', () => {
    // Agent with H.264 HW but no HEVC/AV1/vp9_qsv (old NVIDIA/AMD class):
    // H.264-DC must beat the ≤1920-capped libvpx SW fallback.
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-h264'],
        agentHwEncoders: ['ffmpeg-h264_nvenc', 'libvpx-vp9-444-sw'],
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
        viewerH264Hw: true,
      }),
    )
    expect(r.transport).toBe('data-channel-h264')
    expect(r.chromaOverride).toBeNull()
  })

  it('P2 — VP9 HW×HW still beats H.264-DC (better compression at parity)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-h264'],
        agentHwEncoders: ['ffmpeg-vp9_qsv', 'ffmpeg-h264_qsv', 'libvpx-vp9-444-sw'],
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
        viewerH264Hw: true,
      }),
    )
    expect(r.transport).toBe('data-channel-vp9-444')
  })

  it('P2 — H.264-DC needs the TRANSPORT advertisement (no hw_encoders fallback)', () => {
    // ffmpeg-h264_* entries and the transport ship in the same release —
    // an encoder label without the transport must NOT light the path.
    const r = pickAutoTransport(
      base({
        agentHwEncoders: ['ffmpeg-h264_nvenc'],
        viewerH264Hw: true,
      }),
    )
    expect(r.transport).toBeNull()
  })

  it('P2 — H.264-DC skipped when the viewer lacks HW H.264 decode', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-h264'],
        viewerH264Hw: false,
      }),
    )
    expect(r.transport).toBeNull()
  })

  it('nothing decodable / nothing advertised → webrtc (null)', () => {
    expect(pickAutoTransport(base({})).transport).toBeNull()
  })

  it('derives transports from hw_encoders for pre-transports agent rows', () => {
    // Older DB rows lack `transports` (skip_serializing_if empty) — the
    // hw_encoders labels alone must still light up the HEVC path.
    const r = pickAutoTransport(
      base({
        agentHwEncoders: ['ffmpeg-hevc_nvenc'],
        viewerHevcHw: true,
        viewerHevcDecodable: true,
      }),
    )
    expect(r.transport).toBe('data-channel-hevc')
  })

  // THE CORPLAP-3 case (Edge, 2026-08-25): MediaCapabilities reports HEVC as
  // hardware-smooth (Edge's platform pipeline has HEVC Video Extensions)
  // while WebCodecs refuses `hev1` — the contract the DC worker actually
  // configures against. The rank picked HEVC, configure() failed, the
  // session went black, and the reconnect ladder re-picked it forever.
  // Both halves are required.
  it('HEVC-DC skipped when MediaCapabilities says HW but WebCodecs refuses (Edge)', () => {
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-hevc'],
        agentHwEncoders: ['ffmpeg-hevc_videotoolbox', 'libvpx-vp9-444-sw'],
        viewerHevcHw: true, // MC (the <video> pipeline) says yes…
        viewerHevcDecodable: false, // …WebCodecs says no — MUST win
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).not.toBe('data-channel-hevc')
    expect(r.transport).toBe('data-channel-vp9-444')
  })

  it('HEVC-DC still requires the MC hardware-smooth verdict (rc.186 property)', () => {
    // WebCodecs accepting the config is not enough — isConfigSupported
    // returns true for software / too-slow HEVC, and a weak iGPU then
    // hangs (Iris Xe keyframe spiral). MC smooth+powerEfficient stays a
    // conjunct, exactly as before.
    const r = pickAutoTransport(
      base({
        agentTransports: ['data-channel-vp9-444', 'data-channel-hevc'],
        agentHwEncoders: ['ffmpeg-hevc_nvenc', 'libvpx-vp9-444-sw'],
        viewerHevcHw: false,
        viewerHevcDecodable: true,
        viewerVp9Hw: true,
        viewerVp9Decodable: true,
      }),
    )
    expect(r.transport).not.toBe('data-channel-hevc')
  })
})

describe('displayMatchWireMessage (rc.191)', () => {
  it('sends rounded dims for an enable request', () => {
    expect(displayMatchWireMessage({ width: 1672.4, height: 818.6 })).toEqual({
      t: 'rc:display-match',
      width: 1672,
      height: 819,
    })
  })

  it('null / non-finite dims become a restore request', () => {
    expect(displayMatchWireMessage(null)).toEqual({ t: 'rc:display-match', enable: false })
    expect(displayMatchWireMessage({ width: NaN, height: 800 })).toEqual({
      t: 'rc:display-match',
      enable: false,
    })
  })
})

/** #2638 - the per-connect display-match re-send is made when the session turns
 *  `connected`, before the control channel opens; it is held, and the channel's
 *  open sends it. */
describe('HeldRequest (#2638)', () => {
  it('holds nothing until asked, and gives a held request back once', () => {
    const held = new HeldRequest<{ width: number; height: number } | null>()
    expect(held.take()).toBeNull()
    held.hold({ width: 946, height: 598 })
    expect(held.take()).toEqual({ value: { width: 946, height: 598 } })
    // Taken: the open that sent it cannot send it twice.
    expect(held.take()).toBeNull()
  })

  it('keeps the newest, and a held "turn it off" is a request too', () => {
    const held = new HeldRequest<{ width: number; height: number } | null>()
    held.hold({ width: 946, height: 598 })
    held.hold(null)
    // `null` is a value here, not "nothing held": the toggle went off before
    // the channel opened, and the host must hear that.
    expect(held.take()).toEqual({ value: null })
  })

  it('a new session clears what an earlier one held', () => {
    const held = new HeldRequest<{ width: number; height: number } | null>()
    held.hold({ width: 1280, height: 720 })
    held.clear()
    expect(held.take()).toBeNull()
  })
})

describe('AV1_CODEC_STRING (rc.190)', () => {
  it('is Main profile, level 5.1, Main tier, 8-bit — covers 4K@60', () => {
    // The declared level is a MAX (HEVC L3.1 lesson: too low a level
    // hard-rejects streams above it); 13 = 5.1.
    expect(AV1_CODEC_STRING).toBe('av01.0.13M.08')
  })
})

describe('QueueDrift (FR-59 P3 — transit-queue growth)', () => {
  // µs helpers: the wire timestamp is the agent's clock, the arrival is
  // ours. The two origins are deliberately FAR apart in these tests —
  // that offset is exactly what must cancel.
  const AGENT_EPOCH = 1_000_000
  const LOCAL_EPOCH = 987_654_321

  it('reports zero drift when frames arrive at the cadence they were framed', () => {
    const d = new QueueDrift()
    for (let i = 0; i < 10; i++) {
      d.add(AGENT_EPOCH + i * 33_000, LOCAL_EPOCH + i * 33_000)
    }
    expect(d.snapshotAndReset()).toBe(0)
  })

  it('sums the growth when frames land slower than they were framed', () => {
    // Framed every 33 ms, arriving every 50 ms ⇒ 17 ms behind per frame.
    const d = new QueueDrift()
    for (let i = 0; i < 10; i++) {
      d.add(AGENT_EPOCH + i * 33_000, LOCAL_EPOCH + i * 50_000)
    }
    // 9 intervals × 17 ms — the first frame only establishes the cadence.
    expect(d.snapshotAndReset()).toBe(153)
  })

  it('goes NEGATIVE while the queue drains — a recovering session is not congested', () => {
    const d = new QueueDrift()
    for (let i = 0; i < 5; i++) {
      d.add(AGENT_EPOCH + i * 50_000, LOCAL_EPOCH + i * 33_000)
    }
    expect(d.snapshotAndReset()).toBe(-68)
  })

  it('distinguishes "no frames" from "a stable queue"', () => {
    const d = new QueueDrift()
    // Nothing at all.
    expect(d.snapshotAndReset()).toBeNull()
    // Exactly one frame establishes a cadence but measures no interval.
    d.add(AGENT_EPOCH, LOCAL_EPOCH)
    expect(d.snapshotAndReset()).toBeNull()
  })

  it('drops a pair that straddles a reset or a pause instead of believing it', () => {
    const d = new QueueDrift()
    d.add(AGENT_EPOCH, LOCAL_EPOCH)
    // Wire timestamp went BACKWARDS (encoder rebuild / resync).
    d.add(AGENT_EPOCH - 500_000, LOCAL_EPOCH + 33_000)
    expect(d.snapshotAndReset()).toBeNull()
    // A 30 s idle gap is not a cadence either.
    d.reset()
    d.add(AGENT_EPOCH, LOCAL_EPOCH)
    d.add(AGENT_EPOCH + 30_000_000, LOCAL_EPOCH + 30_000_000)
    expect(d.snapshotAndReset()).toBeNull()
  })

  it('clamps one glitchy pair so it cannot decide the window', () => {
    const d = new QueueDrift()
    d.add(AGENT_EPOCH, LOCAL_EPOCH)
    // Framed 1 ms apart, arrived 4 s apart — real, but a single stall must
    // not read as 4 s of sustained queue growth.
    d.add(AGENT_EPOCH + 1_000, LOCAL_EPOCH + 4_000_000)
    expect(d.snapshotAndReset()).toBe(1000)
  })

  it('reset() drops the cadence so the next pair is not measured across it', () => {
    const d = new QueueDrift()
    d.add(AGENT_EPOCH, LOCAL_EPOCH)
    d.reset()
    d.add(AGENT_EPOCH + 33_000, LOCAL_EPOCH + 999_000)
    expect(d.snapshotAndReset()).toBeNull()
  })
})

describe('decodeStatWireMessage (rc.188 viewer-rate feedback)', () => {
  it('rounds + clamps the reported fps and carries the struggling bit', () => {
    expect(decodeStatWireMessage(58.7, true)).toEqual({
      t: 'rc:decodestat',
      fps: 59,
      struggling: true,
    })
    expect(decodeStatWireMessage(30, false)).toEqual({
      t: 'rc:decodestat',
      fps: 30,
      struggling: false,
    })
  })

  it('FR-15: carries the paint-age window when the clock probe has locked', () => {
    expect(decodeStatWireMessage(30, false, { avgMs: 123.4, minMs: 61.8 })).toEqual({
      t: 'rc:decodestat',
      fps: 30,
      struggling: false,
      age_ms: 123,
      age_min_ms: 62,
    })
  })

  it('FR-15: omits the age entirely when absent — "no signal", not 0 ms', () => {
    // Pre-P7 agents / a window that painted nothing: the agent's age loop
    // must see NO report rather than a fabricated zero (which would read
    // as a perfect path and suppress the loop forever).
    for (const age of [undefined, null, { avgMs: NaN, minMs: 4 }, { avgMs: 4, minMs: Infinity }]) {
      const m = decodeStatWireMessage(30, false, age as never)
      expect(m.age_ms).toBeUndefined()
      expect(m.age_min_ms).toBeUndefined()
    }
  })

  it('FR-59 P3: carries the link report as a pair, independently of the age', () => {
    // No age at all — the whole point is that this signal does not need
    // the clock probe, so it must not be gated behind one.
    expect(decodeStatWireMessage(30, false, null, null, { rxBps: 395_122, queueMs: 240 })).toEqual({
      t: 'rc:decodestat',
      fps: 30,
      struggling: false,
      rx_bps: 395_122,
      queue_ms: 240,
    })
    // A DRAINING queue must survive as a negative number; clamping it at 0
    // would make recovery indistinguishable from stability.
    const m = decodeStatWireMessage(30, false, null, null, { rxBps: 1_000, queueMs: -350 })
    expect(m.queue_ms).toBe(-350)
  })

  it('FR-59 P3: omits the link report when the drift is no-signal', () => {
    // `queueMs: null` = fewer than two frames arrived. Sending rx_bps
    // alone would hand the agent a lower bound it could mistake for
    // capacity, so the pair is all-or-nothing.
    for (const link of [undefined, null, { rxBps: 400_000, queueMs: null }]) {
      const m = decodeStatWireMessage(30, false, null, null, link as never)
      expect(m.rx_bps).toBeUndefined()
      expect(m.queue_ms).toBeUndefined()
    }
  })

  it('FR-59 P3: clamps queue_ms into the i16 the agent packs it into', () => {
    expect(decodeStatWireMessage(30, false, null, null, { rxBps: 1, queueMs: 99_999 }).queue_ms).toBe(
      32767,
    )
    expect(
      decodeStatWireMessage(30, false, null, null, { rxBps: 1, queueMs: -99_999 }).queue_ms,
    ).toBe(-32768)
  })

  it('FR-15 P2: the probe round trip rides along with the age', () => {
    // The agent cannot tell a real path floor from a clock-biased one
    // without it — half of this is the smallest age the path can produce.
    const m = decodeStatWireMessage(30, false, { avgMs: 120, minMs: 61 }, 88.6)
    expect(m.probe_rtt_ms).toBe(89)
  })

  it('FR-15 P2: no round trip is sent without an age, or before a probe lands', () => {
    // Meaningless on its own, and an absent value must read as "no bound"
    // on the agent rather than as a 0 ms path.
    expect(decodeStatWireMessage(30, false, null, 88).probe_rtt_ms).toBeUndefined()
    expect(
      decodeStatWireMessage(30, false, { avgMs: 120, minMs: 61 }, null).probe_rtt_ms,
    ).toBeUndefined()
    expect(
      decodeStatWireMessage(30, false, { avgMs: 120, minMs: 61 }, NaN).probe_rtt_ms,
    ).toBeUndefined()
  })

  it('FR-15: clamps the age into the u16 the agent packs it into', () => {
    const m = decodeStatWireMessage(30, false, { avgMs: 999_999, minMs: -5 })
    expect(m.age_ms).toBe(65535)
    expect(m.age_min_ms).toBe(0)
  })

  it('coerces non-finite / negative fps to 0 (a clean "no useful number")', () => {
    expect(decodeStatWireMessage(NaN, false).fps).toBe(0)
    expect(decodeStatWireMessage(-5, true).fps).toBe(0)
    expect(decodeStatWireMessage(Infinity, false).fps).toBe(0)
  })

  it('caps absurd fps at 240 so the packed 16-bit agent field never overflows', () => {
    expect(decodeStatWireMessage(100000, true).fps).toBe(240)
  })

  // FR-70 M0 — the age at arrival rides only alongside an age (same clock
  // mapping), never on its own, and never as a 0 (the agent's absent
  // sentinel for the slot).
  it('sends arr_ms only alongside age_ms, floored at 1', () => {
    const withAge = decodeStatWireMessage(
      30,
      false,
      { avgMs: 4903, minMs: 61 },
      80,
      null,
      { avgMs: 4890.4 },
    )
    expect(withAge.age_ms).toBe(4903)
    expect(withAge.arr_ms).toBe(4890)
    // No age ⇒ no arrival, whatever the worker measured.
    const noAge = decodeStatWireMessage(30, false, null, null, null, { avgMs: 4890 })
    expect('arr_ms' in noAge).toBe(false)
    // A sub-millisecond arrival age is reported as 1, not 0.
    const tiny = decodeStatWireMessage(30, false, { avgMs: 5, minMs: 2 }, 4, null, { avgMs: 0.2 })
    expect(tiny.arr_ms).toBe(1)
    // Pre-M0 callers omit it entirely.
    expect('arr_ms' in decodeStatWireMessage(30, false, { avgMs: 5, minMs: 2 })).toBe(false)
  })
})

describe('priorityWireMessage (rc.199 Priority dial)', () => {
  it('builds the rc:priority envelope for each dial', () => {
    expect(priorityWireMessage('balanced')).toEqual({ t: 'rc:priority', mode: 'balanced' })
    expect(priorityWireMessage('sharper')).toEqual({ t: 'rc:priority', mode: 'sharper' })
    expect(priorityWireMessage('smoother')).toEqual({ t: 'rc:priority', mode: 'smoother' })
  })
})

describe('codecChoiceToSettings (rc.199 unified Codec picker)', () => {
  it('maps every choice to a full transport/chroma/codec/render tuple', () => {
    expect(codecChoiceToSettings('auto')).toEqual({
      videoTransport: 'auto',
      chroma: 'auto',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    expect(codecChoiceToSettings('av1')).toEqual({
      videoTransport: 'data-channel-av1',
      chroma: 'auto',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    expect(codecChoiceToSettings('hevc')).toEqual({
      videoTransport: 'data-channel-hevc',
      chroma: 'auto',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    // P7 — HEVC Rext 4:4:4 shares the HEVC transport and differs ONLY in
    // chroma (the vp9-444/vp9-420 pattern).
    expect(codecChoiceToSettings('hevc-444')).toEqual({
      videoTransport: 'data-channel-hevc',
      chroma: 'yuv444',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    // The two VP9 choices share a transport and differ ONLY in chroma —
    // 4:4:4 = crisp text, 4:2:0 = efficient.
    expect(codecChoiceToSettings('vp9-444')).toEqual({
      videoTransport: 'data-channel-vp9-444',
      chroma: 'yuv444',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    expect(codecChoiceToSettings('vp9-420')).toEqual({
      videoTransport: 'data-channel-vp9-444',
      chroma: 'yuv420',
      preferredCodec: null,
      renderPath: 'webcodecs',
    })
    // P2 — H.264 now defaults to the DC + WebCodecs pipeline (connect()
    // falls back to the RTP track when either end can't do DC-H.264).
    expect(codecChoiceToSettings('h264')).toEqual({
      videoTransport: 'data-channel-h264',
      chroma: 'auto',
      preferredCodec: 'h264',
      renderPath: 'webcodecs',
    })
  })

  it('P2 — the h264Rtp escape hatch restores the legacy RTP + <video> mapping', () => {
    expect(codecChoiceToSettings('h264', { h264Rtp: true })).toEqual({
      videoTransport: 'webrtc',
      chroma: 'auto',
      preferredCodec: 'h264',
      renderPath: 'video',
    })
  })
})

describe('settingsToCodecChoice (rc.199 reverse map)', () => {
  it('derives the picker value from the stored transport + chroma', () => {
    expect(settingsToCodecChoice('auto', 'auto')).toBe('auto')
    expect(settingsToCodecChoice('data-channel-av1', 'auto')).toBe('av1')
    expect(settingsToCodecChoice('data-channel-hevc', 'auto')).toBe('hevc')
    // P7 — explicit yuv444 on the HEVC transport reads back as the Rext
    // pick; yuv420 (and legacy auto above) stay plain HEVC.
    expect(settingsToCodecChoice('data-channel-hevc', 'yuv444')).toBe('hevc-444')
    expect(settingsToCodecChoice('data-channel-hevc', 'yuv420')).toBe('hevc')
    expect(settingsToCodecChoice('data-channel-vp9-444', 'yuv444')).toBe('vp9-444')
    expect(settingsToCodecChoice('data-channel-vp9-444', 'yuv420')).toBe('vp9-420')
    // FR-77 — a vp9-444 transport with chroma 'auto' is the dial-following
    // VP9 choice (it used to read as 4:2:0 while the agent, given no
    // chroma_pref, actually ran profile 1: the display lied).
    expect(settingsToCodecChoice('data-channel-vp9-444', 'auto')).toBe('vp9')
    expect(settingsToCodecChoice('webrtc', 'auto')).toBe('h264')
    // P2 — both H.264 transports read back as the single picker choice.
    expect(settingsToCodecChoice('data-channel-h264', 'auto')).toBe('h264')
    // FR-77 — codec Auto remembers an explicit chroma.
    expect(settingsToCodecChoice('auto', 'yuv444')).toBe('auto-444')
    expect(settingsToCodecChoice('auto', 'yuv420')).toBe('auto-420')
  })

  it('round-trips every choice through settings and back', () => {
    // FR-77 — EVERY value of the single list, so a choice added to it
    // without a settings mapping fails here instead of in the picker.
    for (const c of RC_CODEC_CHOICES) {
      const s = codecChoiceToSettings(c)
      expect(settingsToCodecChoice(s.videoTransport, s.chroma)).toBe(c)
    }
  })
})

describe('per-agent codec override (2026-07-28)', () => {
  const A = 'agent-aaa'
  const B = 'agent-bbb'
  beforeEach(() => {
    globalThis.localStorage?.removeItem(CODEC_STORAGE_PREFIX + A)
    globalThis.localStorage?.removeItem(CODEC_STORAGE_PREFIX + B)
  })

  it('round-trips an explicit choice per agent', () => {
    persistCodecChoice(A, 'h264')
    expect(readStoredCodecChoice(A)).toBe('h264')
    expect(readStoredCodecChoice(B)).toBeNull()
  })

  it('auto (or null) clears the override via removeItem', () => {
    persistCodecChoice(A, 'hevc')
    persistCodecChoice(A, 'auto')
    expect(globalThis.localStorage?.getItem(CODEC_STORAGE_PREFIX + A)).toBeNull()
    persistCodecChoice(B, 'av1')
    persistCodecChoice(B, null)
    expect(readStoredCodecChoice(B)).toBeNull()
  })

  it('ignores garbage and a stored literal auto', () => {
    globalThis.localStorage?.setItem(CODEC_STORAGE_PREFIX + A, 'mpeg2')
    expect(readStoredCodecChoice(A)).toBeNull()
    globalThis.localStorage?.setItem(CODEC_STORAGE_PREFIX + A, 'auto')
    expect(readStoredCodecChoice(A)).toBeNull()
  })

  it('isolates overrides between agents', () => {
    persistCodecChoice(A, 'h264')
    persistCodecChoice(B, 'vp9-444')
    expect(readStoredCodecChoice(A)).toBe('h264')
    expect(readStoredCodecChoice(B)).toBe('vp9-444')
    persistCodecChoice(A, 'auto')
    expect(readStoredCodecChoice(A)).toBeNull()
    expect(readStoredCodecChoice(B)).toBe('vp9-444')
  })

  it('every explicit picker value survives the storage round-trip', () => {
    // Regression: the storage allow-list was a hand-maintained copy of the
    // RcCodecChoice union and omitted 'hevc-444', so a per-agent HEVC 4:4:4
    // override was persisted and then rejected on read. The list is now the
    // single source both derive from, and this walks every value of it.
    for (const choice of RC_CODEC_CHOICES) {
      if (choice === 'auto') continue
      persistCodecChoice(A, choice)
      expect(readStoredCodecChoice(A)).toBe(choice)
    }
    persistCodecChoice(B, 'hevc-444')
    expect(readStoredCodecChoice(B)).toBe('hevc-444')
  })

  it('connect precedence: fresh pick beats stored override beats nothing', () => {
    // rc.190 guard transplanted: a pre-connect pick wins and gets persisted.
    expect(codecConnectAction(true, 'hevc')).toBe('persist-pick')
    expect(codecConnectAction(true, null)).toBe('persist-pick')
    expect(codecConnectAction(false, 'hevc')).toBe('apply-stored')
    expect(codecConnectAction(false, null)).toBe('none')
  })
})

describe('P7 — HEVC Rext 4:4:4 codec string', () => {
  it('locks the Rext profile fields alongside the Main-profile default', () => {
    // Same Annex-B no-description contract as the worker's default
    // hev1.1.6.L153.B0; profile_idc 4 + the Rext compat flag + Level 5.1.
    expect(HEVC_REXT_CODEC_STRING).toBe('hev1.4.10.L153.B0')
  })
})

// FR-119 P1 — the frame-rate answer rides trailing optional keys of
// rc:video-info, exactly as the agent's `encode::frame_rate::video_info_fields`
// writes them (its Rust test locks the same bytes).
describe('rc:video-info frame rate (FR-119 P1)', () => {
  const head = '{"t":"rc:video-info","codec":"h265","encoder":"hevc_nvenc","hardware":true,"chroma":"yuv420","transport":"direct","native_w":1920,"native_h":1080,"viewers":1'

  it('parses the stream rate and a refused ask with its reason', () => {
    const refused = parseControlInbound(`${head},"fps":60,"fps_asked":120,"fps_reason":"unproven"}`)
    expect(refused?.kind).toBe('video_info')
    if (refused?.kind === 'video_info') {
      expect(refused.info.fps).toBe(60)
      expect(refused.info.fps_asked).toBe(120)
      expect(refused.info.fps_reason).toBe('unproven')
      // FR-119 P2b-3 — `trial` joins the answer: false unless the agent says
      // a trial runs.
      expect(frameRateAnswerOf(refused.info)).toEqual({ fps: 60, asked: 120, reason: 'unproven', trial: false })
    }
    const granted = parseControlInbound(`${head},"fps":60}`)
    if (granted?.kind === 'video_info') {
      expect(granted.info.fps).toBe(60)
      expect('fps_asked' in granted.info).toBe(false)
      expect(frameRateAnswerOf(granted.info)).toEqual({ fps: 60, asked: null, reason: null, trial: false })
    }
  })

  it('carries no frame rate from an agent without fps-high, and drops half a refusal', () => {
    const plain = parseControlInbound(`${head}}`)
    if (plain?.kind === 'video_info') {
      expect('fps' in plain.info).toBe(false)
      expect(frameRateAnswerOf(plain.info)).toBeNull()
    }
    const half = parseControlInbound(`${head},"fps":60,"fps_asked":120}`)
    if (half?.kind === 'video_info') {
      expect('fps_asked' in half.info).toBe(false)
    }
  })
})

// FR-93 P2 — the Linux capture arm rides two trailing optional keys
// (`capture_arm`, `attended`), and the capture pill names it.
describe('rc:video-info capture_arm (FR-93 P2)', () => {
  const head = '{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"direct","native_w":1280,"native_h":800,"viewers":1'

  it('parses capture_arm and attended, and leaves both absent otherwise', () => {
    const mutter = parseControlInbound(`${head},"capture_arm":"mutter","attended":false}`)
    expect(mutter?.kind).toBe('video_info')
    if (mutter?.kind === 'video_info') {
      expect(mutter.info.capture_arm).toBe('mutter')
      expect(mutter.info.attended).toBe(false)
    }
    const portal = parseControlInbound(`${head},"capture_arm":"portal","attended":true}`)
    if (portal?.kind === 'video_info') {
      expect(portal.info.attended).toBe(true)
    }
    // Windows, macOS and older agents send neither key: the parsed info
    // carries neither, so there is no pill at all.
    const plain = parseControlInbound(`${head}}`)
    expect(plain?.kind).toBe('video_info')
    if (plain?.kind === 'video_info') {
      expect('capture_arm' in plain.info).toBe(false)
      expect('attended' in plain.info).toBe(false)
    }
  })

  it('names the arm, and says whether anyone at the screen was asked', () => {
    const vi = (capture_arm: string, attended: boolean) => ({
      codec: 'vp9', encoder: 'libvpx', hardware: false, chroma: 'yuv444', transport: 'direct',
      native_w: 1280, native_h: 800, viewers: 1, capture_arm, attended,
    })
    expect(captureArmLabel(vi('mutter', false))).toBe('GNOME screencast · asks nobody')
    expect(captureArmLabel(vi('drm', false))).toBe('DRM scanout · asks nobody')
    expect(captureArmLabel(vi('portal', true))).toBe('desktop portal · allowed at the screen')
    expect(captureArmLabel(vi('x11', false))).toBe('X11')
    // A newer agent's arm is shown by its own name, never dropped.
    expect(captureArmLabel(vi('pipewire-direct', false))).toBe('pipewire-direct · asks nobody')
    expect(captureArmLabel(null)).toBe('')
    expect(captureArmLabel({ ...vi('x11', false), capture_arm: undefined })).toBe('')
  })
})

describe('parseControlInbound — rc:video-info native dims (rc.199)', () => {
  it('parses native_w/native_h when the agent reports them', () => {
    const parsed = parseControlInbound(
      '{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"relay","native_w":2560,"native_h":1600}',
    )
    expect(parsed).toEqual({
      kind: 'video_info',
      info: {
        codec: 'vp9',
        encoder: 'libvpx',
        hardware: false,
        chroma: 'yuv444',
        transport: 'relay',
        native_w: 2560,
        native_h: 1600,
        // P5 — absent on pre-P5 agents ⇒ defaults to solo.
        viewers: 1,
      },
    })
  })

  it('parses the P5 shared-pipeline viewers count', () => {
    const parsed = parseControlInbound(
      '{"t":"rc:video-info","codec":"h265","encoder":"hevc_nvenc","hardware":true,"chroma":"yuv420","transport":"direct","native_w":1920,"native_h":1080,"viewers":2}',
    )
    expect(parsed?.kind).toBe('video_info')
    if (parsed?.kind === 'video_info') {
      expect(parsed.info.viewers).toBe(2)
    }
  })

  it('parses the FR-33 P3 transport_reason and leaves it absent otherwise', () => {
    const named = parseControlInbound(
      '{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"relay","native_w":2560,"native_h":1600,"viewers":1,"transport_reason":"lan-captured"}',
    )
    expect(named?.kind).toBe('video_info')
    if (named?.kind === 'video_info') {
      expect(named.info.transport_reason).toBe('lan-captured')
    }
    // Pre-P3 agents (and every relay with another cause) omit the key: the
    // parsed object must not carry it at all, so the pill stays plain.
    const plain = parseControlInbound(
      '{"t":"rc:video-info","codec":"vp9","encoder":"libvpx","hardware":false,"chroma":"yuv444","transport":"relay"}',
    )
    expect(plain?.kind).toBe('video_info')
    if (plain?.kind === 'video_info') {
      expect('transport_reason' in plain.info).toBe(false)
    }
  })

  // FR-70 P1 — the cap in force rides two trailing optional keys; the
  // detail never rides without a reason.
  it('parses the FR-70 P1 cap_reason/cap_detail and leaves them absent otherwise', () => {
    const capped = parseControlInbound(
      '{"t":"rc:video-info","codec":"h265","encoder":"hevc_qsv","hardware":true,"chroma":"yuv420","transport":"relay","native_w":1920,"native_h":1200,"viewers":1,"cap_reason":"slow-link-cap","cap_detail":"remembered 200 kbps"}',
    )
    expect(capped?.kind).toBe('video_info')
    if (capped?.kind === 'video_info') {
      expect(capped.info.cap_reason).toBe('slow-link-cap')
      expect(capped.info.cap_detail).toBe('remembered 200 kbps')
    }
    // A detail with no reason is a stray string: dropped.
    const stray = parseControlInbound(
      '{"t":"rc:video-info","codec":"h265","encoder":"hevc_qsv","hardware":true,"chroma":"yuv420","transport":"relay","native_w":1920,"native_h":1200,"viewers":1,"cap_detail":"remembered 200 kbps"}',
    )
    expect(stray?.kind).toBe('video_info')
    if (stray?.kind === 'video_info') {
      expect('cap_reason' in stray.info).toBe(false)
      expect('cap_detail' in stray.info).toBe(false)
    }
    // Pre-P1 agents omit both.
    const plain = parseControlInbound(
      '{"t":"rc:video-info","codec":"h265","encoder":"hevc_qsv","hardware":true,"chroma":"yuv420","transport":"relay","native_w":1920,"native_h":1200,"viewers":1}',
    )
    expect(plain?.kind).toBe('video_info')
    if (plain?.kind === 'video_info') {
      expect('cap_reason' in plain.info).toBe(false)
    }
  })

  // FR-70 P1 — the pill names the cap from the agent's report; the old
  // transport-only guess survives only for agents that report none.
  it('annotates a below-native stream with the cap the agent names', () => {
    const base = {
      codec: 'h265',
      encoder: 'hevc_qsv',
      hardware: true,
      chroma: 'yuv420',
      transport: 'relay',
      native_w: 1920,
      native_h: 1200,
      viewers: 1,
    }
    // The operator's 2026-09-04 session: Native selected, 1280×800 on screen.
    expect(
      resolutionCapAnnotation(
        { ...base, cap_reason: 'slow-link-cap', cap_detail: 'remembered 200 kbps' },
        1280,
        800,
      ),
    ).toBe(' · slow link (remembered 200 kbps) · native 1920×1200')
    expect(resolutionCapAnnotation({ ...base, cap_reason: 'priority-cap' }, 1280, 800)).toBe(
      ' · Priority cap · native 1920×1200',
    )
    // A pre-P1 agent on a relay: the rc.199 guess, unchanged.
    expect(resolutionCapAnnotation(base, 1280, 800)).toBe(' · relay-limited (native 1920×1200)')
    // … and on a direct path it never guessed.
    expect(resolutionCapAnnotation({ ...base, transport: 'direct' }, 1280, 800)).toBe('')
    // At native there is nothing to annotate, whatever the agent says.
    expect(resolutionCapAnnotation({ ...base, cap_reason: 'slow-link-cap' }, 1920, 1200)).toBe('')
    // Unknown dims: nothing.
    expect(resolutionCapAnnotation({ ...base, native_w: 0, native_h: 0 }, 1280, 800)).toBe('')
    expect(resolutionCapAnnotation(null, 1280, 800)).toBe('')

    // The setting's hint says what lifts it — and for the slow-link
    // profile that is NOT the Priority dial.
    const hint = resolutionOverrideHint(
      { ...base, cap_reason: 'slow-link-cap', cap_detail: 'remembered 200 kbps' },
      1280,
      800,
    )
    expect(hint).toContain('capped at 1280×800')
    expect(hint).toContain('remembered 200 kbps')
    expect(hint).toContain('next session')
    expect(hint).not.toContain('Sharper')
    expect(resolutionOverrideHint({ ...base, cap_reason: 'priority-cap' }, 1280, 800)).toContain(
      'Sharper',
    )
    expect(resolutionOverrideHint(base, 1280, 800)).toBe('')
  })

  it('parses the P6 arbiter state broadcast (rc:control.state)', () => {
    const parsed = parseControlInbound(
      '{"t":"rc:control.state","mode":"exclusive","holder":"aabbccdd00112233aabbccdd","participants":[{"session":"aabbccdd00112233aabbccdd","name":"Goran","input":true},{"session":"ffeeddcc00112233aabbccdd","name":"Ana","input":false}]}',
    )
    expect(parsed?.kind).toBe('control_state')
    if (parsed?.kind === 'control_state') {
      expect(parsed.state.mode).toBe('exclusive')
      expect(parsed.state.holder).toBe('aabbccdd00112233aabbccdd')
      expect(parsed.state.participants).toEqual([
        { session: 'aabbccdd00112233aabbccdd', name: 'Goran', input: true },
        { session: 'ffeeddcc00112233aabbccdd', name: 'Ana', input: false },
      ])
    }
    // Free mode + no holder + malformed participants degrade safely.
    const free = parseControlInbound(
      '{"t":"rc:control.state","mode":"free","holder":null,"participants":[{"bogus":1}]}',
    )
    expect(free?.kind).toBe('control_state')
    if (free?.kind === 'control_state') {
      expect(free.state.mode).toBe('free')
      expect(free.state.holder).toBeNull()
      expect(free.state.participants).toEqual([])
    }
  })

  it('FR-27: carries a pending floor request, and degrades to null without one', () => {
    const waiting = parseControlInbound(
      '{"t":"rc:control.state","mode":"exclusive","holder":"aabbccdd00112233aabbccdd","participants":[],"pending_request":{"session":"ffeeddcc00112233aabbccdd","name":"Ana"}}',
    )
    expect(waiting?.kind).toBe('control_state')
    if (waiting?.kind === 'control_state') {
      expect(waiting.state.pendingRequest).toEqual({
        session: 'ffeeddcc00112233aabbccdd',
        name: 'Ana',
      })
    }

    // A pre-FR-27 agent omits the key entirely. That is indistinguishable from
    // "nothing pending", which is the correct degradation: the whole chip
    // self-hides rather than rendering an empty one.
    const older = parseControlInbound(
      '{"t":"rc:control.state","mode":"exclusive","holder":null,"participants":[]}',
    )
    if (older?.kind === 'control_state') expect(older.state.pendingRequest).toBeNull()

    // An explicit null, and a malformed object, must not throw either.
    for (const raw of [
      '{"t":"rc:control.state","mode":"free","holder":null,"participants":[],"pending_request":null}',
      '{"t":"rc:control.state","mode":"free","holder":null,"participants":[],"pending_request":{"name":"no session id"}}',
    ]) {
      const p = parseControlInbound(raw)
      expect(p?.kind).toBe('control_state')
      if (p?.kind === 'control_state') expect(p.state.pendingRequest).toBeNull()
    }
  })

  it('defaults native dims to 0 for older agents that omit them (back-compat)', () => {
    const parsed = parseControlInbound(
      '{"t":"rc:video-info","codec":"h265","encoder":"hevc_nvenc","hardware":true,"chroma":"yuv420","transport":"direct"}',
    )
    expect(parsed?.kind).toBe('video_info')
    if (parsed?.kind === 'video_info') {
      expect(parsed.info.native_w).toBe(0)
      expect(parsed.info.native_h).toBe(0)
    }
  })
})

describe('parseControlInbound — rc:layout (rc.227)', () => {
  it('parses a well-formed layout snapshot', () => {
    const r = parseControlInbound(
      '{"t":"rc:layout","active_hkl":"04070407","active":"de-DE","installed":[{"hkl":"04070407","tag":"de-DE"},{"hkl":"08820402","tag":"bg-BG"}]}',
    )
    expect(r).toEqual({
      kind: 'layout',
      activeHkl: '04070407',
      activeTag: 'de-DE',
      installed: [
        { hkl: '04070407', tag: 'de-DE' },
        { hkl: '08820402', tag: 'bg-BG' },
      ],
    })
  })

  it('defaults a missing installed list to [] and filters malformed entries', () => {
    const r = parseControlInbound('{"t":"rc:layout","active_hkl":"04090409","active":"en-US"}')
    expect(r).toEqual({
      kind: 'layout',
      activeHkl: '04090409',
      activeTag: 'en-US',
      installed: [],
    })
    const r2 = parseControlInbound(
      '{"t":"rc:layout","active_hkl":"04090409","active":"en-US","installed":[{"hkl":"ok-missing-tag"},{"hkl":"04070407","tag":"de-DE"},7,null]}',
    )
    expect(r2?.kind).toBe('layout')
    if (r2?.kind === 'layout') {
      expect(r2.installed).toEqual([{ hkl: '04070407', tag: 'de-DE' }])
    }
  })

  it('rejects snapshots missing the active fields', () => {
    expect(parseControlInbound('{"t":"rc:layout","active":"en-US"}')).toBeNull()
    expect(parseControlInbound('{"t":"rc:layout","active_hkl":"04090409"}')).toBeNull()
  })
})

describe('layoutSetWireMessage (rc.227)', () => {
  it('builds the wire shape the agent control arm validates', () => {
    expect(layoutSetWireMessage('04070407')).toEqual({ t: 'rc:layout.set', hkl: '04070407' })
    expect(layoutSetWireMessage('ABCDEF01')).toEqual({ t: 'rc:layout.set', hkl: 'ABCDEF01' })
  })

  it('refuses anything that is not 1-16 hex digits', () => {
    expect(layoutSetWireMessage('')).toBeNull()
    expect(layoutSetWireMessage('xyz')).toBeNull()
    expect(layoutSetWireMessage('0407 0407')).toBeNull()
    expect(layoutSetWireMessage('0123456789abcdef0')).toBeNull()
  })
})

describe('loopback discovery port range (v2.2 multi-agent + reservation fallback)', () => {
  it('probes the primary band first, then the fallback band', () => {
    // Primary band leads (unchanged behaviour on normal hosts).
    expect(LOCAL_RELAY_PROBE_PORTS[0]).toBe(LOCAL_RELAY_PROBE_PORT)
    expect(LOCAL_RELAY_PROBE_PORTS.slice(0, 5)).toEqual([47989, 47990, 47991, 47992, 47993])
    // Fallback band (below the Hyper-V/WSL/HNS reservation zone) for
    // hosts whose primary band is swallowed by a port-pool reservation.
    expect(LOCAL_RELAY_PROBE_PORTS.slice(5)).toEqual([41989, 41990, 41991, 41992, 41993])
    expect(LOCAL_RELAY_PROBE_PORTS.length).toBe(10)
    // Each band is contiguous and 5 wide (matches agent PROBE_PORT_BAND).
    for (const band of [LOCAL_RELAY_PROBE_PORTS.slice(0, 5), LOCAL_RELAY_PROBE_PORTS.slice(5)]) {
      for (let i = 1; i < band.length; i++) expect(band[i]).toBe(band[i - 1] + 1)
    }
  })

  it('clipboardBridgeUrl builds a loopback URL for any candidate port', () => {
    expect(clipboardBridgeUrl(47989)).toBe('http://127.0.0.1:47989/rc-clipboard')
    expect(clipboardBridgeUrl(41989)).toBe('http://127.0.0.1:41989/rc-clipboard')
  })
})

describe('parseLocalRelayDescriptor (Phase 2 loopback-TURN corp-relay)', () => {
  it('accepts a well-formed descriptor', () => {
    expect(
      parseLocalRelayDescriptor({
        turn_port: 47990,
        overlay_ip: '100.64.0.5',
        username: '1700000600:uid',
        credential: 'abc',
      }),
    ).toEqual({
      turn_port: 47990,
      overlay_ip: '100.64.0.5',
      username: '1700000600:uid',
      credential: 'abc',
    })
  })

  it('rejects malformed / missing / out-of-range blobs (untrusted loopback JSON)', () => {
    const base = { turn_port: 47990, overlay_ip: 'x', username: 'u', credential: 'c' }
    expect(parseLocalRelayDescriptor(null)).toBeNull()
    expect(parseLocalRelayDescriptor('nope')).toBeNull()
    expect(parseLocalRelayDescriptor({})).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, turn_port: 0 })).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, turn_port: 70000 })).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, turn_port: 1.5 })).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, overlay_ip: '' })).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, username: 5 })).toBeNull()
    expect(parseLocalRelayDescriptor({ ...base, credential: undefined })).toBeNull()
  })
})

describe('localRelayIceServer (Phase 2)', () => {
  it('builds the loopback turn: ICE server from a descriptor', () => {
    expect(
      localRelayIceServer({
        turn_port: 47990,
        overlay_ip: '100.64.0.5',
        username: '1700000600:uid',
        credential: 'abc',
      }),
    ).toEqual({
      urls: ['turn:127.0.0.1:47990'],
      username: '1700000600:uid',
      credential: 'abc',
    })
  })

  it('always dials loopback (never the overlay IP — that is the remote agent entry)', () => {
    const s = localRelayIceServer({
      turn_port: 12345,
      overlay_ip: '100.64.9.9',
      username: 'u',
      credential: 'c',
    })
    expect(s.urls[0]).toBe('turn:127.0.0.1:12345')
    expect(s.urls[0]).not.toContain('100.64')
  })
})

describe('storedInputGapMs (FR-98 C3)', () => {
  afterEach(() => {
    localStorage.removeItem(INPUT_GAP_STORAGE_KEY)
  })

  it('keeps the FR-1 P6 gap of 8 ms unless set', () => {
    expect(DEFAULT_INPUT_GAP_MS).toBe(8)
    expect(storedInputGapMs()).toBe(8)
    localStorage.setItem(INPUT_GAP_STORAGE_KEY, 'fast')
    expect(storedInputGapMs()).toBe(8)
  })

  it('takes 0..16, clamping the rest', () => {
    for (const [raw, want] of [
      ['0', 0],
      ['2', 2],
      ['4', 4],
      ['16', 16],
      ['40', 16],
      ['-3', 0],
    ] as const) {
      localStorage.setItem(INPUT_GAP_STORAGE_KEY, raw)
      expect(storedInputGapMs(), raw).toBe(want)
    }
  })
})

describe('storedDecodePref (2026-07-24 decode-stall A/B)', () => {
  afterEach(() => {
    localStorage.removeItem('meshharbor-rc-decode-pref')
  })

  it('maps the localStorage values to VideoDecoder hardwareAcceleration', () => {
    localStorage.setItem('meshharbor-rc-decode-pref', 'software')
    expect(storedDecodePref()).toBe('prefer-software')
    localStorage.setItem('meshharbor-rc-decode-pref', 'hardware')
    expect(storedDecodePref()).toBe('prefer-hardware')
  })

  it('defaults to no-preference (unset or garbage)', () => {
    expect(storedDecodePref()).toBe('no-preference')
    localStorage.setItem('meshharbor-rc-decode-pref', 'banana')
    expect(storedDecodePref()).toBe('no-preference')
  })
})

describe('FR-1 P7 — clock-sync helpers (rc-hop-stats)', () => {
  it('clockSample maps the agent clock onto the browser epoch at the probe midpoint', () => {
    // Probe: sent at 1000µs, echoed back at 1400µs (400µs RTT); the agent
    // read its clock at 5000µs. Midpoint = 1200 → offset 3800, and
    // agentNow ≈ epochNow + offset thereafter.
    const s = clockSample(1000, 1400, 5000)
    expect(s).toEqual({ offsetUs: 3800, rttMs: 0.4 })
  })

  it('clockSample rejects garbage (negative RTT, non-finite inputs)', () => {
    expect(clockSample(2000, 1000, 5000)).toBeNull()
    expect(clockSample(Number.NaN, 1400, 5000)).toBeNull()
    expect(clockSample(1000, Number.POSITIVE_INFINITY, 5000)).toBeNull()
    expect(clockSample(1000, 1400, Number.NaN)).toBeNull()
  })

  it('bestClockSample picks the minimum-RTT sample (NTP-style)', () => {
    const a = { offsetUs: 100, rttMs: 5 }
    const b = { offsetUs: 90, rttMs: 1.2 }
    const c = { offsetUs: 130, rttMs: 8 }
    expect(bestClockSample([a, b, c])).toBe(b)
    expect(bestClockSample([])).toBeNull()
  })

  it('frameAgeMs reads a wire timestamp as age on the browser clock', () => {
    // offset 3800 (from the sample above): a frame stamped at agent-µs
    // 4000 observed at browser epoch-µs 1500 is (1500+3800-4000)/1000 ms old.
    expect(frameAgeMs(4000, 3800, 1500)).toBeCloseTo(1.3)
    // Same instant → age 0.
    expect(frameAgeMs(5300, 3800, 1500)).toBeCloseTo(0)
  })

  it('round-trip: a sample built from a probe makes the probed instant age≈RTT/2', () => {
    // The echo left the agent mid-flight: by receive time (t1) it should
    // read as ~half an RTT old — the asymmetry bound of the method.
    const s = clockSample(1000, 1400, 5000)!
    expect(frameAgeMs(5000, s.offsetUs, 1400)).toBeCloseTo(0.2)
  })
})

describe('P1 — hop-stats helpers (rc-hop-stats)', () => {
  it('HopStats accumulates avg/max per window and resets on snapshot', () => {
    const s = new HopStats()
    s.add(1)
    s.add(2)
    s.add(6)
    const w = s.snapshotAndReset()
    expect(w).toEqual({ avgMs: 3, maxMs: 6, minMs: 1, n: 3 })
    // Window reset — an empty follow-up window reads zeros.
    expect(s.snapshotAndReset()).toEqual({ avgMs: 0, maxMs: 0, minMs: 0, n: 0 })
  })

  it('FR-15: HopStats tracks the window MINIMUM (the path-floor sample)', () => {
    const s = new HopStats()
    // A queued window still contains one frame that rode a drained pipe —
    // that minimum is what the agent uses as the path floor, and the gap
    // to the average is the queue it reacts to.
    s.add(210)
    s.add(64)
    s.add(190)
    const w = s.snapshotAndReset()
    expect(w.minMs).toBe(64)
    expect(w.avgMs).toBeGreaterThan(w.minMs)
    // Reset clears the min too — a following clean window must not
    // inherit the previous one's floor.
    s.add(80)
    expect(s.snapshotAndReset().minMs).toBe(80)
  })

  it('HopStats rounds to 0.1 ms', () => {
    const s = new HopStats()
    s.add(0.14)
    s.add(0.14)
    const w = s.snapshotAndReset()
    expect(w.avgMs).toBe(0.1)
    expect(w.maxMs).toBe(0.1)
  })

  it('HopStats ignores garbage samples (NaN / negative / Infinity)', () => {
    const s = new HopStats()
    s.add(Number.NaN)
    s.add(-5)
    s.add(Number.POSITIVE_INFINITY)
    s.add(2)
    expect(s.snapshotAndReset()).toEqual({ avgMs: 2, maxMs: 2, minMs: 2, n: 1 })
  })

  it('ctxOptionsFor maps the A/B modes (legacy = no options object)', () => {
    expect(ctxOptionsFor('legacy')).toBeUndefined()
    expect(ctxOptionsFor('opaque')).toEqual({ alpha: false })
    expect(ctxOptionsFor('opaque-desync')).toEqual({ alpha: false, desynchronized: true })
  })

  it('normalizeCtxMode defaults unknown values to opaque-desync', () => {
    expect(normalizeCtxMode('legacy')).toBe('legacy')
    expect(normalizeCtxMode('opaque')).toBe('opaque')
    expect(normalizeCtxMode('opaque-desync')).toBe('opaque-desync')
    expect(normalizeCtxMode(null)).toBe('opaque-desync')
    expect(normalizeCtxMode('banana')).toBe('opaque-desync')
  })

  it('round1 rounds to one decimal', () => {
    expect(round1(1.24)).toBe(1.2)
    expect(round1(1.25)).toBe(1.3)
    expect(round1(0)).toBe(0)
  })
})

describe('P1 — viewer diagnosis localStorage knobs', () => {
  afterEach(() => {
    localStorage.removeItem('meshharbor-rc-ctx-mode')
    localStorage.removeItem('meshharbor-rc-per-frame-msg')
    localStorage.removeItem('meshharbor-rc-diag-hud')
  })

  it('storedCtxMode defaults to opaque-desync and honours the A/B values', () => {
    expect(storedCtxMode()).toBe('opaque-desync')
    localStorage.setItem('meshharbor-rc-ctx-mode', 'legacy')
    expect(storedCtxMode()).toBe('legacy')
    localStorage.setItem('meshharbor-rc-ctx-mode', 'opaque')
    expect(storedCtxMode()).toBe('opaque')
    localStorage.setItem('meshharbor-rc-ctx-mode', 'banana')
    expect(storedCtxMode()).toBe('opaque-desync')
  })

  it('storedPerFrameMsg is OFF unless explicitly "1"', () => {
    expect(storedPerFrameMsg()).toBe(false)
    localStorage.setItem('meshharbor-rc-per-frame-msg', '1')
    expect(storedPerFrameMsg()).toBe(true)
    localStorage.setItem('meshharbor-rc-per-frame-msg', 'true')
    expect(storedPerFrameMsg()).toBe(false)
  })

  it('diagHudEnabled is OFF unless explicitly "1"', () => {
    expect(diagHudEnabled()).toBe(false)
    localStorage.setItem('meshharbor-rc-diag-hud', '1')
    expect(diagHudEnabled()).toBe(true)
  })
})

describe('P6 — flow-control knobs + sustained-window struggle rule', () => {
  afterEach(() => {
    localStorage.removeItem('meshharbor-rc-max-queue')
    localStorage.removeItem('meshharbor-rc-struggle-queue')
    localStorage.removeItem('meshharbor-rc-struggle-windows')
  })

  it('storedFlowParams defaults match the pre-P6 baked constants', () => {
    expect(storedFlowParams()).toEqual({
      maxQueue: DEFAULT_MAX_DECODE_QUEUE,
      struggleQueue: DEFAULT_STRUGGLE_QUEUE,
      struggleWindows: DEFAULT_STRUGGLE_WINDOWS,
    })
    // Lock the actual values too — these ARE the wire behaviour.
    expect(storedFlowParams()).toEqual({ maxQueue: 4, struggleQueue: 2, struggleWindows: 2 })
  })

  it('storedFlowParams honours the localStorage overrides with clamps', () => {
    localStorage.setItem('meshharbor-rc-max-queue', '8')
    localStorage.setItem('meshharbor-rc-struggle-queue', '0')
    localStorage.setItem('meshharbor-rc-struggle-windows', '1')
    expect(storedFlowParams()).toEqual({ maxQueue: 8, struggleQueue: 0, struggleWindows: 1 })
    // Out-of-range clamps instead of trusting the raw value.
    localStorage.setItem('meshharbor-rc-max-queue', '9999')
    localStorage.setItem('meshharbor-rc-struggle-windows', '0')
    const clamped = storedFlowParams()
    expect(clamped.maxQueue).toBe(60)
    expect(clamped.struggleWindows).toBe(1)
    // Garbage falls back to the defaults.
    localStorage.setItem('meshharbor-rc-max-queue', 'banana')
    expect(storedFlowParams().maxQueue).toBe(DEFAULT_MAX_DECODE_QUEUE)
  })

  it('normalizeIntKnob parses, truncates, clamps, and defaults', () => {
    expect(normalizeIntKnob('7', 4, 1, 60)).toBe(7)
    expect(normalizeIntKnob(7.9, 4, 1, 60)).toBe(7)
    expect(normalizeIntKnob('0', 4, 1, 60)).toBe(1)
    expect(normalizeIntKnob('-3', 4, 1, 60)).toBe(1)
    expect(normalizeIntKnob('999', 4, 1, 60)).toBe(60)
    expect(normalizeIntKnob(null, 4, 1, 60)).toBe(4)
    expect(normalizeIntKnob(undefined, 4, 1, 60)).toBe(4)
    expect(normalizeIntKnob('', 4, 1, 60)).toBe(4)
    expect(normalizeIntKnob('banana', 4, 1, 60)).toBe(4)
    expect(normalizeIntKnob(Number.NaN, 4, 1, 60)).toBe(4)
  })

  it('StruggleWindow needs the configured consecutive run and resets on one clean window', () => {
    const w = new StruggleWindow(2)
    expect(w.observe(true)).toBe(false) // 1st bad window — not yet
    expect(w.observe(true)).toBe(true) // 2nd consecutive — asserted
    expect(w.observe(true)).toBe(true) // stays asserted while the run continues
    expect(w.observe(false)).toBe(false) // one clean window resets immediately
    expect(w.observe(true)).toBe(false) // streak restarts from zero
    w.observe(true)
    w.reset() // teardown: fresh connection starts clean
    expect(w.observe(true)).toBe(false)
  })

  it('StruggleWindow with windows=1 reproduces the legacy instantaneous rule', () => {
    const w = new StruggleWindow(1)
    expect(w.observe(true)).toBe(true)
    expect(w.observe(false)).toBe(false)
    expect(w.observe(true)).toBe(true)
  })

  it('StruggleWindow sanitizes a nonsense windows count to 1', () => {
    expect(new StruggleWindow(0).observe(true)).toBe(true)
    expect(new StruggleWindow(Number.NaN).observe(true)).toBe(true)
  })
})

describe('remoteCursorCssFor', () => {
  const shape = (css?: string) => ({
    bitmap: {} as ImageBitmap,
    hotspotX: 0,
    hotspotY: 0,
    css,
  })

  it('returns the css keyword of the shape at the current position', () => {
    const state = {
      pos: { x: 10, y: 20, id: 7 },
      shapes: new Map([[7, shape('text')]]),
    }
    expect(remoteCursorCssFor(state)).toBe('text')
  })

  it('returns null when the cursor is hidden (no pos)', () => {
    const state = { pos: null, shapes: new Map([[7, shape('text')]]) }
    expect(remoteCursorCssFor(state)).toBeNull()
  })

  it('returns null for an app-custom shape carrying no css', () => {
    const state = {
      pos: { x: 0, y: 0, id: 3 },
      shapes: new Map([[3, shape(undefined)]]),
    }
    expect(remoteCursorCssFor(state)).toBeNull()
  })

  it('returns null when the shape for the current id is not cached yet', () => {
    const state = { pos: { x: 0, y: 0, id: 9 }, shapes: new Map() }
    expect(remoteCursorCssFor(state)).toBeNull()
  })
})

// ─── S3 viewer resilience — decision-table locks ────────────────────
//
// The reconnect machinery itself lives inside the composable (needs a
// live WS store + PeerConnection), but every DECISION it takes routes
// through the pure helpers below. Locking the tables locks the
// behaviour: which endings auto-reconnect, which signalling errors
// advance the ladder vs kill it, which messages a stale session may
// still deliver, and when a flat frame counter probes vs re-creates.

describe('S3 resilience: isRetryableTerminateReason', () => {
  it('auto-reconnects on involuntary endings only', () => {
    expect(isRetryableTerminateReason('agent_disconnect')).toBe(true)
    expect(isRetryableTerminateReason('error')).toBe(true)
  })

  it('stays terminal on every deliberate ending', () => {
    for (const r of [
      'controller_hangup',
      'agent_hangup',
      'user_denied',
      'consent_timeout',
      // FR-27 - a device with no prompt surface would answer the retry the
      // same way, so retrying is pure noise. Terminal by the allowlist's
      // fail-safe default; asserted here so it stays deliberate.
      'no_prompt_surface',
      'admin_terminated',
      'idle_timeout',
    ]) {
      expect(isRetryableTerminateReason(r)).toBe(false)
    }
  })

  it('treats unknown/missing reasons as terminal (fail-safe)', () => {
    expect(isRetryableTerminateReason(undefined)).toBe(false)
    expect(isRetryableTerminateReason(null)).toBe(false)
    expect(isRetryableTerminateReason('')).toBe(false)
    expect(isRetryableTerminateReason('some_future_reason')).toBe(false)
  })

  it('#2251: never retries an error the device named no_common_codec', () => {
    // The same offer would meet the same refusal: a loop that never says why.
    expect(isRetryableTerminateReason('error', 'no_common_codec')).toBe(false)
    // Every other error still retries, named or not (an older server drops
    // the code and sends the bare `error` it always did).
    expect(isRetryableTerminateReason('error', undefined)).toBe(true)
    expect(isRetryableTerminateReason('error', 'some_future_limit')).toBe(true)
    expect(isRetryableTerminateReason('agent_disconnect', undefined)).toBe(true)
  })
})

describe('FR-27: friendlyEndReason', () => {
  it('tells the three consent outcomes apart', () => {
    const denied = friendlyEndReason('user_denied')!
    const timedOut = friendlyEndReason('consent_timeout')!
    const noSurface = friendlyEndReason('no_prompt_surface')!
    expect(new Set([denied, timedOut, noSurface]).size).toBe(3)
    // The whole point of the wire change: a timeout must not read as a
    // refusal. It says so out loud, because that IS what it used to say.
    expect(timedOut).toMatch(/nobody answered/i)
    expect(timedOut).toMatch(/nothing was declined/i)
    expect(denied).toMatch(/declined/i)
    expect(denied).not.toMatch(/nobody answered/i)
    // And "nobody could be asked" has to name a fix the operator can act on.
    expect(noSurface).toMatch(/desktop app|email/i)
  })

  it('stays silent on a nominal ending', () => {
    for (const r of ['controller_hangup', 'agent_hangup', 'idle_timeout', 'agent_disconnect']) {
      expect(friendlyEndReason(r)).toBeNull()
    }
    expect(friendlyEndReason(undefined)).toBeNull()
    expect(friendlyEndReason('some_future_reason')).toBeNull()
  })

  it("FR-101 P4b: names the org's maximum length when that is the limit that ended it", () => {
    expect(friendlyEndReason('idle_timeout', 'max_duration')).toMatch(/maximum length/)
    // The limit only explains an `idle_timeout`; anything else is unchanged.
    expect(friendlyEndReason('idle_timeout', undefined)).toBeNull()
    expect(friendlyEndReason('idle_timeout', 'some_future_limit')).toBeNull()
    expect(friendlyEndReason('controller_hangup', 'max_duration')).toBeNull()
  })

  it('FR-101 P4b-2: says the session ended for want of activity when the idle limit ended it', () => {
    expect(friendlyEndReason('idle_timeout', 'idle')).toMatch(/no activity/)
    // Not the maximum length's words, and only with the reason it belongs to.
    expect(friendlyEndReason('idle_timeout', 'idle')).not.toMatch(/maximum length/)
    expect(friendlyEndReason('host_disconnect', 'idle')).toBeNull()
  })

  it('#2251: says the browser cannot decode what the device sends, and what would help', () => {
    const msg = friendlyEndReason('error', 'no_common_codec')!
    expect(msg).toMatch(/can't decode/)
    expect(msg).toMatch(/OpenH264/)
    // Not "try again": a retry meets the same refusal.
    expect(msg).not.toMatch(/again/i)
    // The code explains only the `error` it rides on; a bare error is unchanged.
    expect(friendlyEndReason('error', undefined)).toBe('The session could not be established.')
    expect(friendlyEndReason('idle_timeout', 'no_common_codec')).toBeNull()
  })
})

// FR-27 P10 - the host's Disconnect. The `rc:terminate` handler takes one
// decision per ending through these two helpers: `isRetryableTerminateReason`
// says whether the ladder re-creates the session, `endedByHost` whether the
// view says "the person at the device ended it" and offers an explicit
// Reconnect. Locking both locks the behaviour the field log measured wrong
// on 0.4.119: a banner Disconnect followed by an automatic reconnect.
describe('FR-27 P10: the host\'s Disconnect', () => {
  it('stops the reconnect ladder: host_disconnect is terminal and named', () => {
    expect(isRetryableTerminateReason('host_disconnect')).toBe(false)
    expect(endedByHost('host_disconnect')).toBe(true)
  })

  it('leaves an ordinary drop on the ladder', () => {
    for (const r of ['agent_disconnect', 'error']) {
      expect(isRetryableTerminateReason(r)).toBe(true)
      expect(endedByHost(r)).toBe(false)
    }
  })

  it('reads no other ending as the host\'s word', () => {
    // `agent_hangup` included on purpose: older agents sent it from the same
    // button, but the viewer has no proof of that, so it stays a quiet close.
    for (const r of [
      'controller_hangup',
      'agent_hangup',
      'user_denied',
      'consent_timeout',
      'no_prompt_surface',
      'admin_terminated',
      'idle_timeout',
      undefined,
      null,
      '',
      'some_future_reason',
    ]) {
      expect(endedByHost(r)).toBe(false)
    }
  })

  it('is not an error: the sentence belongs to the view, not the error alert', () => {
    expect(friendlyEndReason('host_disconnect')).toBeNull()
  })
})

// #2251 - after a refusal the viewer showed "session ... not found" instead of
// the refusal's own sentence: a scoped session_not_found for a candidate still
// in flight reached failWith. Measured on agent 0.4.139 + hosted-32a9095.
describe('#2251: an error for a session the server already ended', () => {
  it('is fallout once that session is closed', () => {
    expect(isFalloutOfEndedSession('closed', 'abc', 'abc')).toBe(true)
  })

  it('still acts on an error for a live attempt', () => {
    for (const phase of ['requesting', 'awaiting_consent', 'negotiating', 'connected']) {
      expect(isFalloutOfEndedSession(phase, 'abc', 'abc')).toBe(false)
    }
  })

  it('never swallows an error for another session, or an unscoped one', () => {
    expect(isFalloutOfEndedSession('closed', 'other', 'abc')).toBe(false)
    expect(isFalloutOfEndedSession('closed', undefined, 'abc')).toBe(false)
    expect(isFalloutOfEndedSession('closed', null, 'abc')).toBe(false)
    expect(isFalloutOfEndedSession('closed', 'abc', null)).toBe(false)
  })
})

describe('S3 resilience: isRetryableRcErrorCode', () => {
  it('advances the ladder on the three mid-reconnect transients', () => {
    expect(isRetryableRcErrorCode('agent_busy')).toBe(true)
    expect(isRetryableRcErrorCode('agent_offline')).toBe(true)
    expect(isRetryableRcErrorCode('session_not_found')).toBe(true)
  })

  it('fails fast on everything else', () => {
    expect(isRetryableRcErrorCode('forbidden')).toBe(false)
    expect(isRetryableRcErrorCode('invalid_token')).toBe(false)
    expect(isRetryableRcErrorCode(undefined)).toBe(false)
    expect(isRetryableRcErrorCode('')).toBe(false)
  })

  // FR-115 P3 — waiting does not free a slot someone is using, so the
  // ladder must not keep asking: the person ends that session or upgrades.
  it('never retries the org session cap', () => {
    expect(isRetryableRcErrorCode('org_session_limit')).toBe(false)
  })
})

describe('FR-115 P3: friendlyRcError for the org session cap', () => {
  it("shows the server's sentence, which names who holds the slot", () => {
    const sentence =
      "Your organization's plan runs one remote session at a time, and Ana is connected to Office PC right now. End that session, or upgrade the plan for one remote session per user."
    expect(friendlyRcError('org_session_limit', sentence)).toBe(sentence)
  })

  it('still says what to do when the server sent no message', () => {
    const msg = friendlyRcError('org_session_limit', null)
    expect(msg).toContain('one remote session at a time')
    expect(msg).toContain('upgrade')
  })
})

describe('2026-08-05 consent wedge: readyRecoveryAction', () => {
  it('proceeds on a gate-matched Ready with a live PeerConnection', () => {
    expect(readyRecoveryAction(true, true, true)).toBe('proceed')
    expect(readyRecoveryAction(true, true, false)).toBe('proceed')
  })

  it('ignores a Ready for a stale session regardless of pc state', () => {
    expect(readyRecoveryAction(false, true, true)).toBe('ignore')
    expect(readyRecoveryAction(false, false, false)).toBe('ignore')
  })

  it('reschedules (never silently drops) a current-session Ready that lost the pc race', () => {
    // The eternal awaiting_consent wedge: server in Negotiating, Ready
    // processed by nobody. With retry args the ladder must take over.
    expect(readyRecoveryAction(true, false, true)).toBe('reschedule')
  })

  it('fails honestly when there is nothing to retry with', () => {
    expect(readyRecoveryAction(true, false, false)).toBe('fail')
  })
})

describe('FR-100 P2a field: terminateAction', () => {
  it('leaves a failed session failed, whatever the terminate says', () => {
    // Field-caught on prod 2026-10-19: a key-changed refusal sent rc:terminate
    // and failed the session, the server's echo then turned the error into a
    // plain close, and the error view, with "Trust the new key and connect",
    // never showed.
    for (const retryable of [true, false]) {
      for (const canReplay of [true, false]) {
        expect(terminateAction({ phase: 'error', retryable, canReplay })).toBe('keep-error')
      }
    }
  })

  it('reconnects an involuntary end it can replay, and closes everything else', () => {
    expect(terminateAction({ phase: 'connected', retryable: true, canReplay: true })).toBe(
      'reconnect',
    )
    expect(terminateAction({ phase: 'negotiating', retryable: true, canReplay: true })).toBe(
      'reconnect',
    )
    expect(terminateAction({ phase: 'connected', retryable: true, canReplay: false })).toBe(
      'close',
    )
    expect(terminateAction({ phase: 'connected', retryable: false, canReplay: true })).toBe(
      'close',
    )
    expect(terminateAction({ phase: 'idle', retryable: true, canReplay: true })).toBe('close')
    expect(terminateAction({ phase: 'closed', retryable: true, canReplay: true })).toBe('close')
  })
})

describe('S3 resilience: sessionGateAllows', () => {
  it('accepts messages carrying the current session id', () => {
    expect(sessionGateAllows('abc123', 'abc123')).toBe(true)
  })

  it('drops messages from a different (stale) session', () => {
    expect(sessionGateAllows('old111', 'new222')).toBe(false)
  })

  it('drops session-scoped messages when no session is active', () => {
    expect(sessionGateAllows('abc123', null)).toBe(false)
  })

  it('passes messages without a session id (pre-session errors)', () => {
    expect(sessionGateAllows(null, 'abc123')).toBe(true)
    expect(sessionGateAllows(undefined, null)).toBe(true)
    expect(sessionGateAllows('', 'abc123')).toBe(true)
  })

  it('never matches non-string ids', () => {
    expect(sessionGateAllows(123 as unknown, '123')).toBe(true) // non-string → treated as absent
  })
})

describe('rcfix 2026-11-04: the watchdog judges the transport, not frame novelty', () => {
  it('a static screen with a live transport is never torn down at the old 10 s', () => {
    // Media flat for the old fail bound, but bytes kept arriving on the pair
    // (RTCP, control-channel answers, cursor): deadTicks stays 0.
    for (let t = 0; t < RC_STALL_MEDIA_FAIL_TICKS; t++) {
      expect(nextStallAction(t, 0)).not.toBe('reconnect')
    }
  })

  it('re-probes with rc:keyframe while media is flat and the transport alive', () => {
    expect(nextStallAction(RC_STALL_PROBE_TICKS, 0)).toBe('probe')
    expect(nextStallAction(RC_STALL_PROBE_TICKS + 1, 0)).toBe('none')
    expect(nextStallAction(RC_STALL_PROBE_TICKS + RC_STALL_REPROBE_TICKS, 0)).toBe('probe')
  })

  it('a dead pump behind a live peer is re-created after the long media bound', () => {
    expect(nextStallAction(RC_STALL_MEDIA_FAIL_TICKS, 0)).toBe('reconnect')
  })

  it('a dead transport is re-created at the old bound', () => {
    expect(nextStallAction(RC_STALL_FAIL_TICKS, RC_STALL_FAIL_TICKS)).toBe('reconnect')
    expect(nextStallAction(RC_STALL_FAIL_TICKS - 1, RC_STALL_FAIL_TICKS - 1)).toBe('none')
  })

  it('without a deadTicks argument the pre-rcfix rule holds exactly', () => {
    expect(nextStallAction(RC_STALL_FAIL_TICKS)).toBe('reconnect')
    expect(nextStallAction(RC_STALL_FAIL_TICKS - 1)).toBe('none')
  })

  it('any inbound progress, or the agent saying no pixels, resets the dead count', () => {
    expect(nextDeadTicks(5, false, false, false)).toBe(6)
    expect(nextDeadTicks(5, true, false, false)).toBe(0)
    expect(nextDeadTicks(5, false, true, false)).toBe(0)
    expect(nextDeadTicks(5, false, false, true)).toBe(0)
  })

  const report = (entries: Record<string, unknown>[]) =>
    new Map(entries.map((e) => [e.id as string, e])) as unknown as RTCStatsReport

  it('reads the selected candidate pair, never another pair', () => {
    const r = report([
      { id: 'T1', type: 'transport', selectedCandidatePairId: 'P2' },
      { id: 'P1', type: 'candidate-pair', bytesReceived: 999_999, state: 'succeeded', nominated: true },
      { id: 'P2', type: 'candidate-pair', bytesReceived: 1234, state: 'succeeded', nominated: true },
    ])
    expect(transportBytesReceived(r)).toBe(1234)
  })

  it('falls back to the nominated succeeded pair (Firefox), else 0', () => {
    expect(
      transportBytesReceived(
        report([
          { id: 'P1', type: 'candidate-pair', bytesReceived: 50, state: 'in-progress', nominated: false },
          { id: 'P2', type: 'candidate-pair', bytesReceived: 70, state: 'succeeded', nominated: true },
        ]),
      ),
    ).toBe(70)
    expect(transportBytesReceived(report([]))).toBe(0)
  })
})

describe('S3 resilience: nextStallAction', () => {
  it('does nothing below the probe threshold', () => {
    for (let t = 0; t < RC_STALL_PROBE_TICKS; t++) {
      expect(nextStallAction(t)).toBe('none')
    }
  })

  it('probes exactly ONCE, at the probe threshold', () => {
    expect(nextStallAction(RC_STALL_PROBE_TICKS)).toBe('probe')
    // Between probe and fail: waiting for the IDR, no re-probe spam.
    for (let t = RC_STALL_PROBE_TICKS + 1; t < RC_STALL_FAIL_TICKS; t++) {
      expect(nextStallAction(t)).toBe('none')
    }
  })

  it('re-creates the session once the probe goes unanswered', () => {
    expect(nextStallAction(RC_STALL_FAIL_TICKS)).toBe('reconnect')
    expect(nextStallAction(RC_STALL_FAIL_TICKS + 5)).toBe('reconnect')
  })

  it('keeps a real grace window between probe and fail', () => {
    // A live agent needs time to answer the keyframe probe before we
    // declare the pipe dead — at least 2 ticks.
    expect(RC_STALL_FAIL_TICKS - RC_STALL_PROBE_TICKS).toBeGreaterThanOrEqual(2)
  })
})

// FR-93 — the agent said this session will produce no pixels (rc:media-
// unavailable). Measured on the FR-93 lab before this: every attempt received
// the reason, the watchdog tore each one down 10 s later, and after three the
// viewer backed off with "its network may be blocking the connection".
describe('FR-93: an agent that says it cannot capture is believed', () => {
  /** Run the watchdog's two pure decisions over `ticks` frameless seconds. */
  const actionsOver = (ticks: number, agentSaidNoPixels: boolean) => {
    let stall = 0
    const actions: string[] = []
    for (let i = 0; i < ticks; i++) {
      stall = nextStallTicks(stall, false, agentSaidNoPixels)
      actions.push(nextStallAction(stall))
    }
    return actions
  }

  it('a frameless minute after the reason neither probes nor re-creates the session', () => {
    const actions = actionsOver(60, true)
    expect(actions.every((a) => a === 'none')).toBe(true)
  })

  it('without the reason, the same minute still probes and then re-creates (the control)', () => {
    const actions = actionsOver(60, false)
    expect(actions[RC_STALL_PROBE_TICKS - 1]).toBe('probe')
    expect(actions[RC_STALL_FAIL_TICKS - 1]).toBe('reconnect')
  })

  it('progress resets the count, and so does the reason; nothing else does', () => {
    expect(nextStallTicks(9, true, false)).toBe(0)
    expect(nextStallTicks(9, false, true)).toBe(0)
    expect(nextStallTicks(9, false, false)).toBe(10)
  })

  it('a stall count held at zero shows no media_stalled badge', () => {
    const stall = nextStallTicks(RC_STALL_FAIL_TICKS, false, true)
    expect(classifyDegraded({ pcState: 'connected', wsConnected: true, stallTicks: stall })).toBe(null)
  })

  // FR-93 P2d-2 — the agent said it waits for the person at the screen.
  it('a wait is honoured until its deadline plus the grace, and not after', () => {
    const w = { for: 'person_at_screen', deadlineMs: 1_000_000, hint: '' }
    expect(agentIsWaiting(null, 0)).toBe(false)
    expect(agentIsWaiting(w, 999_999)).toBe(true)
    expect(agentIsWaiting(w, 1_000_000 + RC_MEDIA_WAITING_GRACE_MS - 1)).toBe(true)
    expect(agentIsWaiting(w, 1_000_000 + RC_MEDIA_WAITING_GRACE_MS)).toBe(false)
  })

  // FR-93 P5f — the agent's last frame travels on the video channel and its
  // notice on the control one, so a tick that counted frames from before the
  // notice (plus one stats poll) must not end the wait. Measured on the lab:
  // it did, and the watchdog re-created the session 10 s later.
  it('only media counted after the notice settles ends a wait', () => {
    const since = 10_000
    expect(advanceEndsWait(true, 9_500, since)).toBe(false)
    expect(advanceEndsWait(true, since + RC_MEDIA_WAITING_SETTLE_MS - 1, since)).toBe(false)
    expect(advanceEndsWait(true, since + RC_MEDIA_WAITING_SETTLE_MS, since)).toBe(true)
    expect(advanceEndsWait(false, since + 5_000, since)).toBe(false)
  })

  // FR-93 P5b — the overlay says what the host waits for. GNOME's lock screen
  // (#2145) ends no request, so it shows no "if nobody answers" deadline; an
  // unknown `for` from a newer agent reads as the dialog it most likely is.
  it('words the waiting overlay by what the host waits for', () => {
    const lock = mediaWaitingCopy('screen_unlock')
    expect(lock.title).toMatch(/screen to be unlocked/)
    expect(lock.status).toBe('waiting for the screen to be unlocked')
    expect(lock.showsDeadline).toBe(false)
    const dialog = mediaWaitingCopy('person_at_screen')
    expect(dialog.title).toBe('Waiting for the person at the screen to share it.')
    expect(dialog.status).toBe('waiting for the person at the screen')
    expect(dialog.showsDeadline).toBe(true)
    expect(mediaWaitingCopy('something_newer')).toEqual(dialog)
    // FR-93 P3e — a display switched off: it wakes to input, nothing ends.
    const dark = mediaWaitingCopy('display_wake')
    expect(dark.title).toMatch(/display is asleep/)
    expect(dark.status).toBe('waiting for the display to wake')
    expect(dark.showsDeadline).toBe(false)
    // FR-93 P5f — this user's session in the background (a user switch).
    const away = mediaWaitingCopy('session_away')
    expect(away.title).toMatch(/another session/)
    expect(away.status).toBe("waiting for this user's session to be on screen")
    expect(away.showsDeadline).toBe(false)
    // FR-93 P5h — the computer going to sleep: it comes back when it wakes.
    const asleep = mediaWaitingCopy('host_sleep')
    expect(asleep.title).toMatch(/going to sleep/)
    expect(asleep.status).toBe('the computer is asleep')
    expect(asleep.showsDeadline).toBe(false)
  })

  it('FR-93 P5j — a computer going to sleep keeps saying so through the redial, and holds nothing back', () => {
    const now = 1_000_000
    const asleep = { for: 'host_sleep', deadlineMs: now + 120_000, hint: 'This computer is going to sleep.' }
    const kept = waitKeptAcrossReconnect(asleep, now)
    expect(kept).not.toBeNull()
    expect(kept?.for).toBe('host_sleep')
    expect(kept?.hint).toBe(asleep.hint)
    // The notice stays on screen, but its deadline is spent: the watchdog does
    // not wait on it, so a new session that stays silent is re-created as usual.
    expect(agentIsWaiting(kept, now)).toBe(false)
    expect(agentIsWaiting(asleep, now)).toBe(true)
    // Any other wait belonged to the session that ended.
    for (const f of ['person_at_screen', 'screen_unlock', 'display_wake', 'session_away', 'something_newer']) {
      expect(waitKeptAcrossReconnect({ ...asleep, for: f }, now)).toBeNull()
    }
    expect(waitKeptAcrossReconnect(null, now)).toBeNull()
    // A notice already past its deadline stays past it.
    const old = { ...asleep, deadlineMs: now - 600_000 }
    expect(waitKeptAcrossReconnect(old, now)?.deadlineMs).toBe(old.deadlineMs)
    // A session that connects ends the kept notice, but not the live session's
    // own: an ICE flap that session recovers from is not a wake.
    expect(isKeptSleepNotice(kept, now)).toBe(true)
    expect(isKeptSleepNotice(asleep, now)).toBe(false)
    expect(isKeptSleepNotice({ ...kept!, for: 'screen_unlock' }, now)).toBe(false)
    expect(isKeptSleepNotice(null, now)).toBe(false)
  })

  it('a frameless two minutes inside a wait neither probes nor re-creates the session', () => {
    const w = { for: 'person_at_screen', deadlineMs: 120_000, hint: '' }
    let stall = 0
    const actions: string[] = []
    for (let s = 0; s < 120; s++) {
      stall = nextStallTicks(stall, false, agentIsWaiting(w, s * 1000))
      actions.push(nextStallAction(stall))
    }
    expect(actions.every((a) => a === 'none')).toBe(true)
    // Past the deadline and the grace, a silent session counts again (the control).
    for (let s = 120 + RC_MEDIA_WAITING_GRACE_MS / 1000; s < 120 + RC_MEDIA_WAITING_GRACE_MS / 1000 + 30; s++) {
      stall = nextStallTicks(stall, false, agentIsWaiting(w, s * 1000))
      actions.push(nextStallAction(stall))
    }
    expect(actions).toContain('reconnect')
  })

  it('a session that said why it has no frames is not dead air', () => {
    expect(isDeadAir({ mediaEverFlowed: false, connected: true, agentSaidNoPixels: true })).toBe(false)
    // The dead-air rule itself is unchanged.
    expect(isDeadAir({ mediaEverFlowed: false, connected: true, agentSaidNoPixels: false })).toBe(true)
    expect(isDeadAir({ mediaEverFlowed: true, connected: true, agentSaidNoPixels: false })).toBe(false)
    expect(isDeadAir({ mediaEverFlowed: false, connected: false, agentSaidNoPixels: false })).toBe(false)
  })
})

describe('S3 resilience: classifyDegraded', () => {
  const healthy = { pcState: 'connected', wsConnected: true, stallTicks: 0 }

  it('is null while fully healthy', () => {
    expect(classifyDegraded(healthy)).toBeNull()
  })

  it('ranks transport instability above everything', () => {
    expect(
      classifyDegraded({ pcState: 'disconnected', wsConnected: false, stallTicks: 99 }),
    ).toBe('transport_unstable')
  })

  it('reports a media stall only once the probe threshold is reached', () => {
    expect(classifyDegraded({ ...healthy, stallTicks: RC_STALL_PROBE_TICKS - 1 })).toBeNull()
    expect(classifyDegraded({ ...healthy, stallTicks: RC_STALL_PROBE_TICKS })).toBe('media_stalled')
  })

  it('reports signalling-offline as the lowest-priority reason', () => {
    expect(classifyDegraded({ ...healthy, wsConnected: false })).toBe('signalling_offline')
    expect(
      classifyDegraded({ pcState: 'connected', wsConnected: false, stallTicks: RC_STALL_PROBE_TICKS }),
    ).toBe('media_stalled')
  })
})

describe('S3 resilience: timing constants', () => {
  it('keeps the pc-disconnected fuse longer than a normal ICE flap', () => {
    // ICE flaps resolve in ~1-2 s; anything shorter than 3 s would
    // false-positive on every desktop transition.
    expect(RC_PC_DISCONNECTED_GRACE_MS).toBeGreaterThanOrEqual(3000)
    expect(RC_PC_DISCONNECTED_GRACE_MS).toBeLessThanOrEqual(8000)
  })

  it('gives signalling more headroom than the whole reconnect first-step ladder', () => {
    expect(RC_SIGNALING_TIMEOUT_MS).toBeGreaterThanOrEqual(10_000)
  })

  it('watchdog cadence stays at 1 Hz so tick counts read as seconds', () => {
    expect(RC_WATCHDOG_TICK_MS).toBe(1000)
  })
})

describe('createHeldInputTracker (stuck-Alt release, 2026-08-04)', () => {
  it('tracks downs, clears on ups, releaseAll drains + empties', () => {
    const t = createHeldInputTracker()
    t.key(0xe2, true) // AltLeft
    t.key(0x2b, true) // Tab
    t.key(0x2b, false) // Tab released normally
    t.button('left', true) // left mouse
    expect(t.size()).toBe(2)

    const held = t.releaseAll()
    expect(held.keys).toEqual([0xe2])
    expect(held.buttons).toEqual(['left'])
    expect(t.size()).toBe(0)
    // Idempotent: nothing left to release.
    expect(t.releaseAll()).toEqual({ keys: [], buttons: [] })
  })

  it('alt-tab scenario: down-down then blur leaves exactly the un-upped keys', () => {
    const t = createHeldInputTracker()
    // Browser sees AltLeft down + Tab down, then the window blurs and the
    // matching keyups never fire — this is the field-reported stuck Alt.
    t.key(0xe2, true)
    t.key(0x2b, true)
    const held = t.releaseAll()
    expect(held.keys).toEqual([0xe2, 0x2b])
  })

  it('re-press after release is tracked fresh (no ghost state)', () => {
    const t = createHeldInputTracker()
    t.key(0xe1, true)
    t.releaseAll()
    t.key(0xe1, true)
    expect(t.releaseAll().keys).toEqual([0xe1])
  })

  it('duplicate downs collapse (auto-repeat must not multiply releases)', () => {
    const t = createHeldInputTracker()
    t.key(0x04, true)
    t.key(0x04, true)
    t.key(0x04, true)
    expect(t.releaseAll().keys).toEqual([0x04])
  })
})

describe('PR-1 rehome: rehomeRetryDecision', () => {
  it('re-keys and redials for every attempt up to the cap', () => {
    for (let n = 1; n <= RC_REHOME_MAX_REDIALS; n++) {
      expect(rehomeRetryDecision(n)).toBe('redial_retry')
    }
  })

  it('falls back to the plain ladder past the cap (no terminal, rc.23)', () => {
    expect(rehomeRetryDecision(RC_REHOME_MAX_REDIALS + 1)).toBe('ladder_only')
    expect(rehomeRetryDecision(100)).toBe('ladder_only')
  })
})

describe('PR-1 rehome: expectedOrgTid', () => {
  const org = '69a1dbbad2000f26adc875ce'
  const other = '68ffffffffffffffffffffff'

  it('prefers the explicit org id (cross-org device modals)', () => {
    expect(expectedOrgTid(other, `/tenant/${org}/agent/x/remote`)).toBe(other)
  })

  it('ignores a malformed explicit id and falls back to the URL', () => {
    expect(expectedOrgTid('not-hex', `/tenant/${org}/agent/x/remote`)).toBe(org)
    expect(expectedOrgTid('', `/tenant/${org}/dashboard`)).toBe(org)
  })

  it('extracts the tenant from any /tenant/<hex> path', () => {
    expect(expectedOrgTid(null, `/tenant/${org}/agent/abc/remote`)).toBe(org)
    expect(expectedOrgTid(undefined, `/tenant/${org}`)).toBe(org)
  })

  it('returns null off tenant-scoped pages', () => {
    expect(expectedOrgTid(null, '/dashboard')).toBeNull()
    expect(expectedOrgTid(null, '/tenant/nothex/agent')).toBeNull()
    expect(expectedOrgTid(null, '')).toBeNull()
  })
})

describe('FR-115 P4b: turnCredsPath', () => {
  const org = '69a1dbbad2000f26adc875ce'
  const agent = '6a975e17971e2d55ddcdeda1'

  it('names the device and its org, for the server to charge', () => {
    expect(turnCredsPath(agent, org)).toBe(
      `/turn/credentials?tenant_id=${org}&agent_id=${agent}`,
    )
  })

  it('falls back to the plain path without both ids', () => {
    expect(turnCredsPath(agent, null)).toBe('/turn/credentials')
    expect(turnCredsPath(agent, 'not-hex')).toBe('/turn/credentials')
    // An external session names its device by a connect code, not an id.
    expect(turnCredsPath('ABCD-1234', org)).toBe('/turn/credentials')
    expect(turnCredsPath('', org)).toBe('/turn/credentials')
  })
})

describe('PR-1 rehome: friendlyRcError', () => {
  it('never echoes server prose for agent_on_other_pod (pod IPs stay internal)', () => {
    const msg = friendlyRcError(
      'agent_on_other_pod',
      'agent is homed on pod 10.10.20.11; re-dial and retry',
    )
    expect(msg).not.toContain('10.10.20.11')
    expect(msg).not.toContain('pod')
  })

  it('maps the known codes to human copy', () => {
    expect(friendlyRcError('agent_offline', 'agent 6a6c9749 is not online')).toContain('offline')
    expect(friendlyRcError('agent_busy', null)).toContain('session limit')
    expect(friendlyRcError('forbidden', null)).toContain('permission')
    expect(friendlyRcError('invalid_token', null)).toContain('expired')
  })

  it('falls back to the server message for unknown codes', () => {
    expect(friendlyRcError('weird_new_code', 'something novel happened')).toBe(
      'something novel happened',
    )
    expect(friendlyRcError('weird_new_code', null)).toBe('weird_new_code')
    expect(friendlyRcError(undefined, undefined)).toBe('signalling error')
  })
})

describe('P7 — FSR sharpening sizing policy (computeRenderTarget)', () => {
  it('off / bad inputs / no viewport all degrade to the 1:1 blit path', () => {
    const blit = { w: 1024, h: 640, scale: 1, pass: 'blit' }
    expect(computeRenderTarget(1024, 640, 1920, 1200, 1.25, 'off')).toEqual(blit)
    // No viewport report yet (synthetic-canvas phase).
    expect(computeRenderTarget(1024, 640, 0, 0, 1, 'auto')).toEqual(blit)
    // Garbage decoded dims.
    expect(computeRenderTarget(0, 0, 1920, 1200, 1, 'auto').pass).toBe('blit')
    expect(computeRenderTarget(Number.NaN, 640, 1920, 1200, 1, 'auto').pass).toBe('blit')
    // Garbage viewport.
    expect(computeRenderTarget(1024, 640, Number.NaN, 1200, 1, 'auto').pass).toBe('blit')
    expect(computeRenderTarget(1024, 640, -5, 1200, 1, 'auto').pass).toBe('blit')
  })

  it('downscale case: auto stays 2D, on sharpens at decoded size', () => {
    // Stream LARGER than the window (2560×1600 into a 1280×800 box).
    expect(computeRenderTarget(2560, 1600, 1280, 800, 1, 'auto').pass).toBe('blit')
    const on = computeRenderTarget(2560, 1600, 1280, 800, 1, 'on')
    expect(on.pass).toBe('rcas')
    expect(on.w).toBe(2560)
    expect(on.h).toBe(1600)
  })

  it('near-1:1 upscale sharpens without EASU', () => {
    // 1.03× need ≤ RCAS_ONLY_MAX_SCALE → rcas at decoded size.
    const t = computeRenderTarget(1000, 625, 1030, 644, 1, 'auto')
    expect(t.pass).toBe('rcas')
    expect(t.w).toBe(1000)
    expect(t.h).toBe(625)
    expect(RCAS_ONLY_MAX_SCALE).toBeCloseTo(1.05)
  })

  it('the field case: Smoother 1024×640 in a 1920×1200 CSS box at 1.25 dpr → 2048×1280 EASU', () => {
    // needScale = min(1920·1.25/1024, 1200·1.25/640) = 2.34 → capped at 2.0.
    const t = computeRenderTarget(1024, 640, 1920, 1200, 1.25, 'auto')
    expect(t.pass).toBe('easu-rcas')
    expect(t.w).toBe(1024 * FSR_MAX_SCALE)
    expect(t.h).toBe(640 * FSR_MAX_SCALE)
  })

  it('uncapped upscale renders at the window need and keeps the decoded aspect', () => {
    // needScale = 1.875 (1920/1024 = 1200/640) — under the 2× cap.
    const t = computeRenderTarget(1024, 640, 1920, 1200, 1, 'auto')
    expect(t.pass).toBe('easu-rcas')
    expect(t.w).toBe(1920)
    expect(t.h).toBe(1200)
    expect(t.w / t.h).toBeCloseTo(1024 / 640, 5)
  })

  it('letterbox: the contain min-axis drives the scale', () => {
    // A wider-than-stream box (2400×1200): height is the binding axis.
    const t = computeRenderTarget(1024, 640, 2400, 1200, 1, 'auto')
    expect(t.pass).toBe('easu-rcas')
    expect(t.h).toBe(1200)
    expect(t.w).toBe(Math.round(1024 * (1200 / 640)))
  })

  it('the 4096 axis cap bounds huge streams (and can crush to rcas-only)', () => {
    // 3840 decoded × 2 dpr would want 2×; the axis cap allows only
    // 4096/3840 ≈ 1.067 → still EASU but at the capped size.
    const capped = computeRenderTarget(3840, 2160, 3840, 2160, 2, 'auto')
    expect(capped.w).toBeLessThanOrEqual(FSR_MAX_AXIS)
    expect(capped.pass).toBe('easu-rcas')
    // 4090 decoded: cap ratio 4096/4090 ≈ 1.0015 ≤ 1.05 → rcas at decoded.
    const crushed = computeRenderTarget(4090, 2160, 8000, 4400, 2, 'auto')
    expect(crushed.pass).toBe('rcas')
    expect(crushed.w).toBe(4090)
  })

  it('dpr is clamped to [1, 4]', () => {
    // dpr 0.5 clamps to 1 → need 1.875× (not 0.94× which would blit).
    expect(computeRenderTarget(1024, 640, 1920, 1200, 0.5, 'auto').pass).toBe('easu-rcas')
    // dpr 10 clamps to 4 — target still bounded by the 2× scale cap.
    const t = computeRenderTarget(1024, 640, 1920, 1200, 10, 'auto')
    expect(t.w).toBe(2048)
  })

  it('normalizeSharpenMode / normalizeSharpness default and clamp', () => {
    expect(normalizeSharpenMode('auto')).toBe('auto')
    expect(normalizeSharpenMode('on')).toBe('on')
    expect(normalizeSharpenMode('off')).toBe('off')
    // Default reverted to 'auto' (2026-08-31): 'on' ran RCAS at 1:1 and
    // amplified per-frame quantisation drift into a static-content shimmer.
    expect(normalizeSharpenMode('banana')).toBe('auto')
    expect(normalizeSharpenMode(null)).toBe('auto')
    expect(normalizeSharpness('0.25')).toBe(0.25)
    expect(normalizeSharpness(1.5)).toBe(1.5)
    expect(normalizeSharpness('9')).toBe(2)
    expect(normalizeSharpness('-1')).toBe(0)
    expect(normalizeSharpness('banana')).toBe(DEFAULT_RCAS_SHARPNESS)
    expect(normalizeSharpness(undefined)).toBe(DEFAULT_RCAS_SHARPNESS)
  })

  it('easuConstants matches the hand-computed FsrEasuCon for the field pair', () => {
    const c = easuConstants(1024, 640, 2048, 1280)
    // con0 — output→input scale + half-texel bias.
    expect(c[0]).toBeCloseTo(0.5, 6)
    expect(c[1]).toBeCloseTo(0.5, 6)
    expect(c[2]).toBeCloseTo(-0.25, 6)
    expect(c[3]).toBeCloseTo(-0.25, 6)
    // con1 — input texel steps.
    expect(c[4]).toBeCloseTo(1 / 1024, 9)
    expect(c[5]).toBeCloseTo(1 / 640, 9)
    expect(c[7]).toBeCloseTo(-1 / 640, 9)
    // con2/con3.
    expect(c[8]).toBeCloseTo(-1 / 1024, 9)
    expect(c[9]).toBeCloseTo(2 / 640, 9)
    expect(c[13]).toBeCloseTo(4 / 640, 9)
    expect(c[15]).toBe(0)
  })
})

describe('P7 — FSR localStorage knobs', () => {
  afterEach(() => {
    localStorage.removeItem('meshharbor-rc-sharpen')
    localStorage.removeItem('meshharbor-rc-fsr-sharpness')
  })

  // FR-26 flipped the default to 'on', but 'on' runs RCAS at 1:1 and turned
  // per-frame quantisation drift into a static-content shimmer (field
  // 2026-08-31). Reverted the default to 'auto' — sharpen only when upscaling.
  it('storedSharpenMode defaults to AUTO and honours on/off', () => {
    expect(storedSharpenMode()).toBe('auto')
    localStorage.setItem('meshharbor-rc-sharpen', 'off')
    expect(storedSharpenMode()).toBe('off')
    localStorage.setItem('meshharbor-rc-sharpen', 'on')
    expect(storedSharpenMode()).toBe('on')
    localStorage.setItem('meshharbor-rc-sharpen', 'banana')
    expect(storedSharpenMode()).toBe('auto')
  })

  // FR-26 — per-pill toolbar toggles.
  it('storedMetricToggles: everything on except the pipeline HUD', () => {
    const m = storedMetricToggles()
    expect(m).toEqual({
      codec: true,
      bitrate: true,
      fps: true,
      resolution: true,
      age: true,
      scale: true,
      paint: false,
    })
    expect(m).toEqual(DEFAULT_RC_METRICS)
  })

  it('storedMetricToggles falls back PER KEY, so a stored older shape still works', () => {
    // Written by a build that only knew three pills: the keys it never
    // heard of must read as their defaults, not as false.
    localStorage.setItem(
      'meshharbor-rc-metrics',
      JSON.stringify({ codec: false, bitrate: true, paint: true }),
    )
    expect(storedMetricToggles()).toEqual({
      codec: false,
      bitrate: true,
      fps: true,
      resolution: true,
      age: true,
      scale: true,
      paint: true,
    })
  })

  it('storedMetricToggles survives corrupt or hostile storage', () => {
    for (const junk of ['{not json', '[]', 'null', '42', '"nope"']) {
      localStorage.setItem('meshharbor-rc-metrics', junk)
      expect(storedMetricToggles()).toEqual(DEFAULT_RC_METRICS)
    }
  })

  it('paint inherits the legacy meshharbor-rc-diag-hud flag exactly once', () => {
    // Anyone who set the undiscoverable flag by hand keeps their HUD; once
    // the checkbox is used, the stored object wins.
    localStorage.setItem('meshharbor-rc-diag-hud', '1')
    expect(storedMetricToggles().paint).toBe(true)
    persistMetricToggles({ ...DEFAULT_RC_METRICS, paint: false })
    expect(storedMetricToggles().paint).toBe(false)
  })

  it('persistMetricToggles round-trips through storage', () => {
    const wanted = { ...DEFAULT_RC_METRICS, fps: false, age: false, paint: true }
    persistMetricToggles(wanted)
    expect(storedMetricToggles()).toEqual(wanted)
  })

  it('storedSharpness defaults to 0.25 and clamps overrides', () => {
    expect(storedSharpness()).toBe(DEFAULT_RCAS_SHARPNESS)
    localStorage.setItem('meshharbor-rc-fsr-sharpness', '0.5')
    expect(storedSharpness()).toBe(0.5)
    localStorage.setItem('meshharbor-rc-fsr-sharpness', '99')
    expect(storedSharpness()).toBe(2)
    localStorage.setItem('meshharbor-rc-fsr-sharpness', 'banana')
    expect(storedSharpness()).toBe(DEFAULT_RCAS_SHARPNESS)
  })
})

// ─── FR-13 (#789): mac-host Ctrl→Cmd translation ─────────────────────────

describe('translateModifierForHost (FR-13 mac Ctrl→Cmd)', () => {
  it('rewrites left/right Control to LeftGui when enabled', () => {
    const state = { ctrlHeldAsCmd: false }
    expect(translateModifierForHost(0xe0, true, true, state)).toBe(0xe3)
    expect(state.ctrlHeldAsCmd).toBe(true)
    expect(translateModifierForHost(0xe0, false, true, state)).toBe(0xe3)
    expect(state.ctrlHeldAsCmd).toBe(false)

    expect(translateModifierForHost(0xe4, true, true, state)).toBe(0xe3)
    expect(translateModifierForHost(0xe4, false, true, state)).toBe(0xe3)
  })

  it('passes Control through untouched when disabled (literal-Ctrl toggle)', () => {
    const state = { ctrlHeldAsCmd: false }
    expect(translateModifierForHost(0xe0, true, false, state)).toBe(0xe0)
    expect(translateModifierForHost(0xe0, false, false, state)).toBe(0xe0)
  })

  it('release matches what was SENT, not the toggle at release time', () => {
    // Toggle flipped OFF while Ctrl held-as-Cmd: the up must still release
    // Cmd (0xe3) or the host is left with Cmd stuck down.
    const state = { ctrlHeldAsCmd: false }
    expect(translateModifierForHost(0xe0, true, true, state)).toBe(0xe3)
    expect(translateModifierForHost(0xe0, false, false, state)).toBe(0xe3)
    expect(state.ctrlHeldAsCmd).toBe(false)

    // And the mirror: pressed literal (disabled), toggle flipped ON before
    // release — the up stays literal Ctrl.
    expect(translateModifierForHost(0xe0, true, false, state)).toBe(0xe0)
    expect(translateModifierForHost(0xe0, false, true, state)).toBe(0xe0)
  })

  it('never touches non-Control usages (letters, Shift, Alt, Meta)', () => {
    const state = { ctrlHeldAsCmd: false }
    for (const code of [0x06 /* c */, 0x19 /* v */, 0xe1 /* shift */, 0xe2 /* alt */, 0xe3 /* meta */]) {
      expect(translateModifierForHost(code, true, true, state)).toBe(code)
      expect(translateModifierForHost(code, false, true, state)).toBe(code)
    }
  })
})

describe('FR-77 — pickAutoTransport honours the chroma axis', () => {
  const pair = {
    agentTransports: ['data-channel-av1', 'data-channel-hevc', 'data-channel-vp9-444', 'data-channel-h264'],
    agentHwEncoders: ['ffmpeg-av1_nvenc', 'ffmpeg-hevc_nvenc', 'ffmpeg-h264_nvenc', 'libvpx-vp9-444-sw'],
    viewerAv1Hw: true,
    viewerHevcHw: true,
    viewerHevcDecodable: true,
    viewerVp9Hw: true,
    viewerVp9Decodable: true,
    viewerH264Hw: true,
  }

  it('an explicit 4:4:4 takes the HEVC Rext cell ahead of the AV1 HW×HW pair', () => {
    const pick = pickAutoTransport({ ...pair, chromaPref: 'yuv444', agentHevc444: true, viewerHevcRext: true })
    expect(pick.transport).toBe('data-channel-hevc')
    expect(pick.chromaOverride).toBe('yuv444')
  })

  it('an explicit 4:4:4 settles for VP9 profile 1 when the pair has no HEVC Rext', () => {
    const pick = pickAutoTransport({ ...pair, chromaPref: 'yuv444', agentHevc444: false, viewerHevcRext: true })
    expect(pick.transport).toBe('data-channel-vp9-444')
    expect(pick.chromaOverride).toBe('yuv444')
    const noBrowser = pickAutoTransport({ ...pair, chromaPref: 'yuv444', agentHevc444: true, viewerHevcRext: false })
    expect(noBrowser.transport).toBe('data-channel-vp9-444')
    expect(noBrowser.chromaOverride).toBe('yuv444')
  })

  it('an explicit 4:4:4 with no 4:4:4 cell at all falls back to the normal rank', () => {
    const pick = pickAutoTransport({ ...pair, chromaPref: 'yuv444', agentHevc444: false, viewerHevcRext: false, viewerVp9Decodable: false })
    expect(pick.transport).toBe('data-channel-av1')
    expect(pick.chromaOverride).toBeNull()
  })

  it('Sharper on chroma Auto takes the HEVC Rext cell when both ends have it, and nothing else', () => {
    const rext = pickAutoTransport({ ...pair, priority: 'sharper', chromaPref: 'auto', agentHevc444: true, viewerHevcRext: true })
    expect(rext.transport).toBe('data-channel-hevc')
    expect(rext.chromaOverride).toBe('yuv444')
    // Without the Rext cell, Sharper keeps today's rank (AV1 HW×HW first)…
    const noRext = pickAutoTransport({ ...pair, priority: 'sharper', chromaPref: 'auto', agentHevc444: false, viewerHevcRext: true })
    expect(noRext.transport).toBe('data-channel-av1')
    // …and Balanced never reaches for Rext.
    const balanced = pickAutoTransport({ ...pair, priority: 'balanced', chromaPref: 'auto', agentHevc444: true, viewerHevcRext: true })
    expect(balanced.transport).toBe('data-channel-av1')
  })

  it('an explicit 4:2:0 pins the libvpx rung to profile 0 even under Sharper', () => {
    const swOnly = {
      ...pair,
      agentTransports: ['data-channel-vp9-444'],
      agentHwEncoders: ['libvpx-vp9-444-sw'],
      viewerAv1Hw: false,
      viewerHevcHw: false,
      viewerH264Hw: false,
    }
    expect(pickAutoTransport({ ...swOnly, priority: 'sharper', chromaPref: 'auto' }).chromaOverride).toBe('yuv444')
    expect(pickAutoTransport({ ...swOnly, priority: 'sharper', chromaPref: 'yuv420' }).chromaOverride).toBe('yuv420')
  })

  it('callers that predate the chroma axis get exactly the rc.190 rank', () => {
    const pick = pickAutoTransport(pair)
    expect(pick.transport).toBe('data-channel-av1')
    expect(pick.chromaOverride).toBeNull()
  })
})

describe('FR-77 P3b — pickAutoTransport reaches hardware-encoded 4:4:4 before libvpx', () => {
  const nvidia = {
    agentTransports: ['data-channel-hevc', 'data-channel-h264', 'data-channel-vp9-444'],
    agentHwEncoders: ['ffmpeg-hevc_nvenc', 'ffmpeg-h264_nvenc', 'libvpx-vp9-444-sw'],
    viewerAv1Hw: false,
    viewerHevcHw: true,
    viewerHevcDecodable: true,
    viewerVp9Hw: true,
    viewerVp9Decodable: true,
    viewerH264Hw: true,
  }

  it('explicit 4:4:4 without HEVC Rext decode takes H.264 High 4:4:4 (HW encode, SW decode)', () => {
    const pick = pickAutoTransport({
      ...nvidia,
      chromaPref: 'yuv444',
      agentHevc444: true,
      viewerHevcRext: false,
      agentH264_444: true,
      viewerH264High444: true,
    })
    expect(pick.transport).toBe('data-channel-h264')
    expect(pick.chromaOverride).toBe('yuv444')
  })

  it('explicit 4:4:4 on an Intel host takes VP9 profile 1 on vp9_qsv before libvpx', () => {
    const pick = pickAutoTransport({
      ...nvidia,
      agentTransports: ['data-channel-h264', 'data-channel-vp9-444'],
      agentHwEncoders: ['ffmpeg-h264_qsv', 'ffmpeg-vp9_qsv', 'libvpx-vp9-444-sw'],
      chromaPref: 'yuv444',
      agentVp9Hw444: true,
      viewerH264High444: true,
      agentH264_444: false,
    })
    expect(pick.transport).toBe('data-channel-vp9-444')
    expect(pick.chromaOverride).toBe('yuv444')
    expect(pick.reason).toContain('vp9_qsv')
  })

  it('the HEVC Rext pair still wins, and Sharper-on-Auto does not take the software-decode cells', () => {
    const rext = pickAutoTransport({
      ...nvidia,
      chromaPref: 'yuv444',
      agentHevc444: true,
      viewerHevcRext: true,
      agentH264_444: true,
      viewerH264High444: true,
    })
    expect(rext.transport).toBe('data-channel-hevc')
    const sharper = pickAutoTransport({
      ...nvidia,
      priority: 'sharper',
      chromaPref: 'auto',
      agentHevc444: false,
      agentH264_444: true,
      viewerH264High444: true,
    })
    expect(sharper.transport).toBe('data-channel-hevc')
    expect(sharper.chromaOverride).toBeNull()
  })

  it('h264-444 is a stored choice that round-trips through the settings', () => {
    const s = codecChoiceToSettings('h264-444')
    expect(s).toMatchObject({ videoTransport: 'data-channel-h264', chroma: 'yuv444' })
    expect(settingsToCodecChoice('data-channel-h264', 'yuv444')).toBe('h264-444')
    expect(settingsToCodecChoice('data-channel-h264', 'auto')).toBe('h264')
    expect(settingsToCodecChoice('webrtc', 'yuv444')).toBe('h264')
  })
})

describe("FR-74 P4 — the viewer's pixel chain (displayScale)", () => {
  // The operator's 2026-09-07 setup: a 1920×1200 native frame on a
  // 1345.33×840.67 CSS stage at 150 % display scaling — a 2018×1261 FSR
  // canvas, i.e. every remote pixel spread over 1.05 screen pixels. That
  // resample happens AFTER the codec, which is why AC1's pixel comparison
  // had to switch the stage to a 1:1 canvas before it meant anything.
  const stage = { stageW: 1345.33, stageH: 840.67, dpr: 1.5 }
  const frame = { frameW: 1920, frameH: 1200 }

  it('names the adaptive upscale and the way to 1:1', () => {
    const s = displayScale({ ...frame, ...stage, mode: 'adaptive', customPct: 100, sharpened: true })
    expect(s.scale).toBeCloseTo(1.051, 3)
    expect(s.label).toBe('shown at 1.05×')
    expect(s.hint).toContain('spread over 1.05 screen pixels')
    expect(s.hint).toContain('FSR sharpens')
    expect(s.hint).toContain('Custom zoom 66.7 %')
    expect(s.hint).toContain("Match remote display so the host renders at your window's 2018×1261")
    // 150 % scaling is named, because Original is then 1.5× on screen.
    expect(s.hint).toContain('your display scaling is 1.5×')
  })

  it('Original is 1:1 in CSS pixels only — 1.5× on screen at 150 % scaling', () => {
    const s = displayScale({ ...frame, ...stage, mode: 'original', customPct: 100 })
    expect(s.label).toBe('shown at 1.50×')
  })

  it('Custom zoom 66.7 % at 150 % scaling IS pixel-exact, and 67 % is not', () => {
    const exact = displayScale({ ...frame, ...stage, mode: 'custom', customPct: 66.7 })
    expect(exact.label).toBe('1:1 pixels')
    expect(exact.hint).toContain('Pixel-exact')
    const near = displayScale({ ...frame, ...stage, mode: 'custom', customPct: 67 })
    expect(near.label).toBe('shown at 1.01×')
  })

  it('Match remote display verified: a frame at the window size is 1:1 in adaptive', () => {
    const s = displayScale({ frameW: 2018, frameH: 1261, ...stage, mode: 'adaptive', customPct: 100 })
    expect(s.label).toBe('1:1 pixels')
  })

  it('a frame larger than the window is a downscale, and the recipe says it will scroll', () => {
    const s = displayScale({ frameW: 2560, frameH: 1600, stageW: 1345.33, stageH: 840.67, dpr: 1, mode: 'adaptive', customPct: 100 })
    expect(s.scale).toBeCloseTo(0.5255, 3)
    expect(s.label).toBe('shown at 0.53×')
    expect(s.hint).toContain('fine detail is lost')
    expect(s.hint).toContain('Custom zoom 100 %')
    expect(s.hint).toContain('will scroll')
  })

  it('is silent until both the frame and the stage are known', () => {
    expect(displayScale({ frameW: 0, frameH: 0, ...stage, mode: 'adaptive', customPct: 100 }).label).toBe('')
    expect(displayScale({ ...frame, stageW: 0, stageH: 0, dpr: 1, mode: 'adaptive', customPct: 100 }).scale).toBeNull()
    // A bogus devicePixelRatio reads as 1 rather than poisoning the label.
    expect(displayScale({ ...frame, stageW: 1920, stageH: 1200, dpr: Number.NaN, mode: 'adaptive', customPct: 100 }).label).toBe('1:1 pixels')
  })
})

/** FR-80 — the status pill's pre-`video-info` label.
 *
 *  The regression this locks: the pill hardcoded "VP9" for any active
 *  DataChannel worker, and that worker decodes VP9, AV1 and H.264 alike. A
 *  session whose host could not capture never receives `rc:video-info`, so an
 *  H.264 session reported "VP9 4:4:4" and sent the operator to the codec
 *  picker instead of the host's screen-recording permission (field,
 *  2026-09-08). */
describe('codecLabelFromDecoderConfig', () => {
  it('names the codec the DECODER was configured with, not the worker', () => {
    // The exact strings the three DC paths configure.
    expect(codecLabelFromDecoderConfig('avc1.640034')).toBe('H.264')
    expect(codecLabelFromDecoderConfig('av01.0.13M.08')).toBe('AV1')
    expect(codecLabelFromDecoderConfig('vp09.00.10.08')).toBe('VP9')
    expect(codecLabelFromDecoderConfig('hev1.1.6.L153.B0')).toBe('H.265')
    // The H.264 4:4:4 profile string is still H.264.
    expect(codecLabelFromDecoderConfig('avc1.f40034')).toBe('H.264')
    expect(codecLabelFromDecoderConfig('hvc1.1.6.L120.B0')).toBe('H.265')
  })

  it('says nothing rather than guessing', () => {
    // Before a decoder is configured there is no codec to name, and naming
    // one anyway is the whole defect.
    expect(codecLabelFromDecoderConfig(null)).toBe('')
    expect(codecLabelFromDecoderConfig(undefined)).toBe('')
    expect(codecLabelFromDecoderConfig('')).toBe('')
    expect(codecLabelFromDecoderConfig('something-new.1')).toBe('')
  })

  it('is case-insensitive, because the string comes from a browser API', () => {
    expect(codecLabelFromDecoderConfig('AVC1.640034')).toBe('H.264')
    expect(codecLabelFromDecoderConfig('AV01.0.13M.08')).toBe('AV1')
  })
})

describe('the record channel (FR-85 P3c)', () => {
  /** A PeerConnection that only records which channels were opened on it. */
  function fakePc() {
    const opened: string[] = []
    return {
      opened,
      pc: {
        createDataChannel: (label: string) => {
          opened.push(label)
          return { label } as unknown as RTCDataChannel
        },
      },
    }
  }

  it('reads RECORD out of the effective grant, by equality, and never assumes it', () => {
    expect(grantHoldsRecord('VIEW | INPUT | CLIPBOARD | FILES | RECORD')).toBe(true)
    expect(grantHoldsRecord('VIEW|RECORD')).toBe(true)
    expect(grantHoldsRecord('VIEW | INPUT')).toBe(false)
    // A newer bit that merely starts with RECORD is not RECORD.
    expect(grantHoldsRecord('VIEW | RECORDING')).toBe(false)
    // An older server sends no grant: absent means no.
    expect(grantHoldsRecord(undefined)).toBe(false)
    expect(grantHoldsRecord(null)).toBe(false)
  })

  it('is opened from the grant, once per PeerConnection, and only when it holds RECORD', () => {
    const { opened, pc } = fakePc()
    const channels: Record<string, RTCDataChannel> = {}
    expect(openRecordChannel(pc, channels, 'VIEW | INPUT')).toBeNull()
    expect(openRecordChannel(pc, channels, null)).toBeNull()
    const ch = openRecordChannel(pc, channels, 'VIEW | RECORD')
    expect(ch).not.toBeNull()
    expect(channels.record).toBe(ch)
    // A second create for the same session (the coalesce echo) opens nothing.
    expect(openRecordChannel(pc, channels, 'VIEW | RECORD')).toBeNull()
    expect(opened).toEqual(['record'])
    // No PeerConnection (a create racing teardown): nothing to open it on.
    expect(openRecordChannel(null, {}, 'VIEW | RECORD')).toBeNull()
  })
})

describe('X14 — download-only child WebRTC offer proof & striped download', () => {
  const SESSION_ID = '507f1f77bcf86cd799439011'
  const AGENT_ID = '507f1f77bcf86cd799439012'
  const USER_ID = '507f1f77bcf86cd799439013'
  const CHILD_IDS = [
    '607f1f77bcf86cd799439021',
    '607f1f77bcf86cd799439022',
    '607f1f77bcf86cd799439023',
    '607f1f77bcf86cd799439024',
  ]
  const SAMPLE_SDP =
    'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
    'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n'

  it('signs and verifies a domain-separated FileChildOfferProof over fileChildOfferTranscript', async () => {
    const {
      FILE_CHILD_OFFER_LABEL,
      fileChildOfferTranscript,
      generateEphemeralFileChildKeyPair,
      signFileChildOfferProof,
      verifyPeerAuth,
      newPeerAuthNonce,
    } = await import('@/utils/peerAuth')

    const keyMat = await generateEphemeralFileChildKeyPair()
    const nonce = newPeerAuthNonce()
    const transcript = fileChildOfferTranscript({
      sessionId: SESSION_ID,
      childId: CHILD_IDS[0],
      transferId: 'dl-stripe-test',
      agentId: AGENT_ID,
      controllerUserId: USER_ID,
      offerSdp: SAMPLE_SDP,
      nonce,
    })
    expect(transcript).not.toBeNull()
    const labelBytes = new TextDecoder().decode(
      transcript!.subarray(0, FILE_CHILD_OFFER_LABEL.length),
    )
    expect(labelBytes).toBe(FILE_CHILD_OFFER_LABEL)

    const proof = await signFileChildOfferProof({
      pair: keyMat.pair,
      publicKeyB64: keyMat.publicKeyB64,
      sessionId: SESSION_ID,
      childId: CHILD_IDS[0],
      transferId: 'dl-stripe-test',
      agentId: AGENT_ID,
      controllerUserId: USER_ID,
      offerSdp: SAMPLE_SDP,
      nonce,
    })
    expect(proof).not.toBeNull()
    expect(await verifyPeerAuth(proof!.key, transcript!, proof!.sig)).toBe(true)

    // Rejects non-canonical ObjectIds or control characters in transferId
    expect(
      fileChildOfferTranscript({
        sessionId: 'not-an-oid',
        childId: CHILD_IDS[0],
        transferId: 'dl-stripe-test',
        agentId: AGENT_ID,
        controllerUserId: USER_ID,
        offerSdp: SAMPLE_SDP,
        nonce,
      }),
    ).toBeNull()
    expect(
      fileChildOfferTranscript({
        sessionId: SESSION_ID,
        childId: CHILD_IDS[0],
        transferId: 'bad\nname',
        agentId: AGENT_ID,
        controllerUserId: USER_ID,
        offerSdp: SAMPLE_SDP,
        nonce,
      }),
    ).toBeNull()
  })

  it('reassembles 4 concurrent download stripes in order and aborts child PCs on rc:file.child.revoke without dropping parent session', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')
    const { fileChildOfferTranscript, verifyPeerAuth } = await import('@/utils/peerAuth')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc

    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) {
        h({ t, ...msg })
      }
    }

    const sentWs: Record<string, unknown>[] = []
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet

    class FakeDc {
      label: string
      readyState = 'open'
      binaryType = 'arraybuffer'
      bufferedAmount = 0
      onopen: (() => void) | null = null
      onclose: (() => void) | null = null
      onmessage: ((ev: { data: string | ArrayBuffer }) => void) | null = null
      sent: Array<string | ArrayBuffer> = []
      closed = false
      constructor(label: string) {
        this.label = label
      }
      send(data: string | ArrayBuffer) {
        this.sent.push(data)
        this.onSend?.(data)
      }
      onSend?: (data: string | ArrayBuffer) => void
      close() {
        this.closed = true
        this.readyState = 'closed'
      }
    }

    class FakePc {
      static instances: FakePc[] = []
      dcs = new Map<string, FakeDc>()
      closed = false
      connectionState = 'connected'
      signalingState: RTCSignalingState = 'stable'
      localDesc: RTCSessionDescriptionInit | null = null
      remoteDesc: RTCSessionDescriptionInit | null = null
      onicecandidate: ((ev: { candidate: { toJSON: () => RTCIceCandidateInit } | null }) => void) | null = null
      onconnectionstatechange: (() => void) | null = null
      ontrack: ((ev: unknown) => void) | null = null
      constructor() {
        FakePc.instances.push(this)
      }
      addTransceiver() {}
      createDataChannel(label: string) {
        const dc = new FakeDc(label)
        this.dcs.set(label, dc)
        return dc as unknown as RTCDataChannel
      }
      async createOffer() {
        return { type: 'offer' as const, sdp: SAMPLE_SDP }
      }
      async setLocalDescription(desc: RTCSessionDescriptionInit) {
        this.localDesc = desc
        this.signalingState = 'have-local-offer'
        // Emit an immediate ICE candidate during setLocalDescription to verify
        // child candidates are buffered until after rc:file.sdp.offer is sent.
        this.onicecandidate?.({
          candidate: {
            toJSON: () => ({
              candidate: 'candidate:1 1 udp 2130706431 127.0.0.1 9999 typ host',
              sdpMid: '0',
              sdpMLineIndex: 0,
            }),
          },
        })
      }
      async setRemoteDescription(desc: RTCSessionDescriptionInit) {
        if (this.signalingState !== 'have-local-offer') {
          throw new Error(`InvalidStateError: setRemoteDescription in ${this.signalingState}`)
        }
        this.remoteDesc = desc
        this.signalingState = 'stable'
      }
      async addIceCandidate() {}
      async getStats() {
        return new Map() as unknown as RTCStatsReport
      }
      close() {
        this.closed = true
        this.connectionState = 'closed'
      }
    }

    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakePc as unknown as typeof RTCPeerConnection

    const writtenChunks: Uint8Array[] = []
    let writableClosed = false
    let writableAborted: unknown = null
    const win = window as unknown as Record<string, unknown>
    const origPicker = win.showSaveFilePicker
    win.showSaveFilePicker = async () => ({
      createWritable: async () => ({
        write: async (data: Uint8Array | ArrayBuffer) => {
          const u8 = data instanceof Uint8Array ? data : new Uint8Array(data)
          writtenChunks.push(u8.slice())
        },
        close: async () => {
          writableClosed = true
        },
        abort: async (reason?: unknown) => {
          writableAborted = reason ?? 'aborted'
        },
      }),
    })

    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
          files: ['resume'] as ('resume')[],
        },
      })
      globalThis.localStorage?.removeItem('meshharbor-rc-download-children')
      const rcDefault = useRemoteControl(agentRef, {
        userId: () => USER_ID,
      })
      expect(rcDefault.concurrentDownloadChildren.value).toBe(0)

      const rc = useRemoteControl(agentRef, {
        userId: () => USER_ID,
        childDownloadConnections: 4,
      })
      expect(rc.concurrentDownloadChildren.value).toBe(4)

      await rc.connect(AGENT_ID)
      const sessionReq = sentWs.find((m) => m.t === 'rc:session.request')
      expect(sessionReq).toBeDefined()
      expect(sessionReq!.browser_caps).toContain('file-child-download')

      const parentPc = FakePc.instances[0]!
      deliverRc('rc:session.created', {
        session_id: SESSION_ID,
        agent_id: AGENT_ID,
        permissions: 'VIEW | INPUT | CLIPBOARD | FILES',
      })
      deliverRc('rc:ready', { session_id: SESSION_ID })
      await new Promise((r) => setTimeout(r, 10))
      deliverRc('rc:sdp.answer', { session_id: SESSION_ID, sdp: SAMPLE_SDP })
      await new Promise((r) => setTimeout(r, 10))
      parentPc.connectionState = 'connected'
      parentPc.onconnectionstatechange?.()
      expect(rc.phase.value).toBe('connected')

      const controlDc = parentPc.dcs.get('control')!
      const parentFilesDc = parentPc.dcs.get('files')!

      // Source payload: 100 bytes [0..99]
      const sourceBytes = new Uint8Array(100)
      for (let i = 0; i < 100; i++) sourceBytes[i] = i

      let registeredKey: string | null = null
      controlDc.onSend = (raw) => {
        if (typeof raw !== 'string') return
        const msg = JSON.parse(raw) as { t?: string; key?: string; child_id?: string }
        if (msg.t === 'rc:file.child.register' && msg.key) {
          registeredKey = msg.key
          controlDc.onmessage?.({ data: JSON.stringify({ t: 'rc:file.child.register.ack' }) })
        } else if (msg.t === 'rc:file.child.prepare' && msg.child_id) {
          controlDc.onmessage?.({
            data: JSON.stringify({ t: 'rc:file.child.prepare.ack', child_id: msg.child_id }),
          })
        }
      }

      parentFilesDc.onSend = (raw) => {
        if (typeof raw !== 'string') return
        const msg = JSON.parse(raw) as { t?: string; id?: string; offset?: number; length?: number }
        if (msg.t === 'files:get' && msg.offset === 0 && msg.length === 0 && msg.id) {
          parentFilesDc.onmessage?.({
            data: JSON.stringify({
              t: 'files:offer',
              id: msg.id,
              name: 'striped.bin',
              size: sourceBytes.length,
              mime: 'application/octet-stream',
            }),
          })
          parentFilesDc.onmessage?.({
            data: JSON.stringify({ t: 'files:eof', id: msg.id, bytes: 0 }),
          })
        }
      }

      let reserveIdx = 0
      ws.sendRaw = (rawMsg: unknown) => {
        const msg = rawMsg as Record<string, unknown>
        sentWs.push(msg)
        if (msg.t === 'rc:file.child.reserve') {
          const cid = CHILD_IDS[reserveIdx++ % CHILD_IDS.length]!
          queueMicrotask(() => {
            deliverRc('rc:file.child.reserved', {
              session_id: SESSION_ID,
              child_id: cid,
              transfer_id: msg.transfer_id,
            })
          })
        } else if (msg.t === 'rc:file.sdp.offer') {
          const cid = String(msg.child_id)
          const childPcIdx = CHILD_IDS.indexOf(cid) + 1
          const childPc = FakePc.instances[childPcIdx]!
          const childFilesDc = childPc.dcs.get('files')!
          childFilesDc.onSend = (raw) => {
            if (typeof raw !== 'string') return
            const req = JSON.parse(raw) as {
              t?: string
              id?: string
              offset?: number
              length?: number
            }
            if (req.t === 'files:get' && typeof req.offset === 'number' && typeof req.length === 'number') {
              const slice = sourceBytes.slice(req.offset, req.offset + req.length)
              // Complete stripes in reverse order (stripe 3 first, stripe 0 last)
              setTimeout(() => {
                childFilesDc.onmessage?.({
                  data: JSON.stringify({
                    t: 'files:offer',
                    id: req.id,
                    name: 'striped.bin',
                    size: req.length,
                  }),
                })
                childFilesDc.onmessage?.({ data: slice.buffer })
                childFilesDc.onmessage?.({
                  data: JSON.stringify({ t: 'files:eof', id: req.id, bytes: req.length }),
                })
              }, (4 - childPcIdx) * 5)
            }
          }
          queueMicrotask(() => {
            deliverRc('rc:file.sdp.answer', {
              session_id: SESSION_ID,
              child_id: cid,
              sdp: SAMPLE_SDP,
            })
            childFilesDc.onopen?.()
          })
        }
      }

      const result = await rc.downloadFile('/var/data/striped.bin', 'striped.bin', {
        childConnections: 4,
      })
      expect(result).toEqual({ name: 'striped.bin', bytes: 100 })
      expect(writableClosed).toBe(true)
      expect(registeredKey).not.toBeNull()

      // Verify all 4 child SDP offers carried valid P-256 proofs under registeredKey
      const childOffers = sentWs.filter((m) => m.t === 'rc:file.sdp.offer')
      expect(childOffers).toHaveLength(4)
      for (const offer of childOffers) {
        const proof = offer.proof as { nonce: string; key: string; sig: string }
        expect(proof.key).toBe(registeredKey)
        const transcript = fileChildOfferTranscript({
          sessionId: SESSION_ID,
          childId: String(offer.child_id),
          transferId: String(offer.transfer_id),
          agentId: AGENT_ID,
          controllerUserId: USER_ID,
          offerSdp: String(offer.sdp),
          nonce: proof.nonce,
        })
        expect(transcript).not.toBeNull()
        expect(await verifyPeerAuth(proof.key, transcript!, proof.sig)).toBe(true)
      }

      // Verify all 4 children sent rc:file.child.complete with matching transfer_id
      const completes = sentWs.filter((m) => m.t === 'rc:file.child.complete')
      expect(completes).toHaveLength(4)
      for (const c of completes) {
        expect(typeof c.transfer_id).toBe('string')
        expect((c.transfer_id as string).length).toBeGreaterThan(0)
      }

      // Verify setLocalDescription's synchronous ICE candidates were buffered
      // until AFTER each child's rc:file.sdp.offer was sent on the wire
      for (const cid of CHILD_IDS) {
        const offerIdx = sentWs.findIndex((m) => m.t === 'rc:file.sdp.offer' && m.child_id === cid)
        const iceIdx = sentWs.findIndex((m) => m.t === 'rc:file.ice' && m.child_id === cid)
        expect(offerIdx).toBeGreaterThanOrEqual(0)
        expect(iceIdx).toBeGreaterThan(offerIdx)
      }

      // Verify reassembled bytes match sourceBytes in order
      const reassembled = new Uint8Array(100)
      let pos = 0
      for (const c of writtenChunks) {
        reassembled.set(c, pos)
        pos += c.byteLength
      }
      expect(Array.from(reassembled)).toEqual(Array.from(sourceBytes))

      // Now test mid-download revocation via rc:file.child.revoke:
      writtenChunks.length = 0
      writableClosed = false
      writableAborted = null
      reserveIdx = 0

      // Hold child answers so download is in flight when revoke arrives
      ws.sendRaw = (rawMsg: unknown) => {
        const msg = rawMsg as Record<string, unknown>
        sentWs.push(msg)
        if (msg.t === 'rc:file.child.reserve') {
          const cid = CHILD_IDS[reserveIdx++ % CHILD_IDS.length]!
          queueMicrotask(() => {
            deliverRc('rc:file.child.reserved', {
              session_id: SESSION_ID,
              child_id: cid,
              transfer_id: msg.transfer_id,
            })
          })
        }
      }

      const inFlightPromise = rc.downloadFile('/var/data/revoked.bin', 'revoked.bin', {
        childConnections: 4,
        sizeHint: 100,
      })
      await new Promise((r) => setTimeout(r, 20))

      // Trigger mid-session child capability revocation
      deliverRc('rc:file.child.revoke', {
        session_id: SESSION_ID,
        reason: 'policy_changed',
      })

      await expect(inFlightPromise).rejects.toThrow(/file child capability revoked/)
      expect(rc.fileChildRevoked.value).toBe(true)
      expect(writableAborted).toBeTruthy()
      // Parent session remains connected and unharmed
      expect(rc.phase.value).toBe('connected')
      expect(parentPc.closed).toBe(false)
      // All child PCs created for the second download are closed
      for (const childPc of FakePc.instances.slice(5)) {
        expect(childPc.closed).toBe(true)
      }

      // A child-attributed rc:error (code === 'file_child_error') does not fail the parent session
      deliverRc('rc:error', {
        session_id: SESSION_ID,
        code: 'file_child_error',
        message: 'file child transports revoked for this session',
      })
      expect(rc.phase.value).toBe('connected')

      // After fileChildRevoked=true, a parent-session rc:error MUST still failWith
      deliverRc('rc:error', {
        session_id: SESSION_ID,
        code: 'permission_denied',
        message: 'session revoked by administrator',
      })
      expect(rc.phase.value).toBe('error')
      expect(rc.error.value).toBeTruthy()

      rc.disconnect()
    } finally {
      globalThis.RTCPeerConnection = origPc
      win.showSaveFilePicker = origPicker
      api.get = origApiGet
      ws.onRcMessage = origOnRc
    }
  })

  it('streams 4 concurrent upload stripes strictly within receiver credit windows and aborts on rc:file.child.revoke', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')
    const { fileChildOfferTranscript, verifyPeerAuth } = await import('@/utils/peerAuth')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc

    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) {
        h({ t, ...msg })
      }
    }

    const sentWs: Record<string, unknown>[] = []
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet

    class FakeDc {
      label: string
      readyState = 'open'
      binaryType = 'arraybuffer'
      bufferedAmount = 0
      bufferedAmountLowThreshold = 0
      onopen: (() => void) | null = null
      onclose: (() => void) | null = null
      onmessage: ((ev: { data: string | ArrayBuffer }) => void) | null = null
      sent: Array<string | ArrayBuffer> = []
      closed = false
      constructor(label: string) {
        this.label = label
      }
      send(data: string | ArrayBuffer) {
        this.sent.push(data)
        this.onSend?.(data)
      }
      onSend?: (data: string | ArrayBuffer) => void
      close() {
        this.closed = true
        this.readyState = 'closed'
      }
    }

    class FakePc {
      static instances: FakePc[] = []
      dcs = new Map<string, FakeDc>()
      closed = false
      connectionState = 'connected'
      signalingState: RTCSignalingState = 'stable'
      localDesc: RTCSessionDescriptionInit | null = null
      remoteDesc: RTCSessionDescriptionInit | null = null
      onicecandidate:
        | ((ev: { candidate: { toJSON: () => RTCIceCandidateInit } | null }) => void)
        | null = null
      onconnectionstatechange: (() => void) | null = null
      ontrack: ((ev: unknown) => void) | null = null
      constructor() {
        FakePc.instances.push(this)
      }
      addTransceiver() {}
      createDataChannel(label: string) {
        const dc = new FakeDc(label)
        this.dcs.set(label, dc)
        return dc as unknown as RTCDataChannel
      }
      async createOffer() {
        return { type: 'offer' as const, sdp: SAMPLE_SDP }
      }
      async setLocalDescription(desc: RTCSessionDescriptionInit) {
        this.localDesc = desc
        this.signalingState = 'have-local-offer'
      }
      async setRemoteDescription(desc: RTCSessionDescriptionInit) {
        if (this.signalingState !== 'have-local-offer') {
          throw new Error(`InvalidStateError: setRemoteDescription in ${this.signalingState}`)
        }
        this.remoteDesc = desc
        this.signalingState = 'stable'
      }
      async addIceCandidate() {}
      async getStats() {
        return new Map() as unknown as RTCStatsReport
      }
      close() {
        this.closed = true
        this.connectionState = 'closed'
      }
    }

    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakePc as unknown as typeof RTCPeerConnection

    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
          files: ['resume'] as ('resume')[],
        },
      })
      globalThis.localStorage?.removeItem('meshharbor-rc-download-children')
      globalThis.localStorage?.removeItem('meshharbor-rc-upload-children')

      // Default is OFF (0) for both directions independently
      const rcDefault = useRemoteControl(agentRef, {
        userId: () => USER_ID,
      })
      expect(rcDefault.concurrentDownloadChildren.value).toBe(0)
      expect(rcDefault.concurrentUploadChildren.value).toBe(0)

      // Opt in ONLY to upload children (download remains 0 = OFF)
      const rc = useRemoteControl(agentRef, {
        userId: () => USER_ID,
        childUploadConnections: 4,
      })
      expect(rc.concurrentDownloadChildren.value).toBe(0)
      expect(rc.concurrentUploadChildren.value).toBe(4)

      await rc.connect(AGENT_ID)
      const sessionReq = sentWs.find((m) => m.t === 'rc:session.request')
      expect(sessionReq).toBeDefined()
      expect(sessionReq!.browser_caps).toContain('file-child-upload')
      expect(sessionReq!.browser_caps).not.toContain('file-child-download')

      const parentPc = FakePc.instances[0]!
      deliverRc('rc:session.created', {
        session_id: SESSION_ID,
        agent_id: AGENT_ID,
        permissions: 'VIEW | INPUT | CLIPBOARD | FILES',
      })
      deliverRc('rc:ready', { session_id: SESSION_ID })
      await new Promise((r) => setTimeout(r, 10))
      deliverRc('rc:sdp.answer', { session_id: SESSION_ID, sdp: SAMPLE_SDP })
      await new Promise((r) => setTimeout(r, 10))
      parentPc.connectionState = 'connected'
      parentPc.onconnectionstatechange?.()
      expect(rc.phase.value).toBe('connected')

      const controlDc = parentPc.dcs.get('control')!
      let registeredKey: string | null = null
      const preparedDirections: string[] = []
      controlDc.onSend = (raw) => {
        if (typeof raw !== 'string') return
        const msg = JSON.parse(raw) as {
          t?: string
          key?: string
          child_id?: string
          direction?: string
        }
        if (msg.t === 'rc:file.child.register' && msg.key) {
          registeredKey = msg.key
          controlDc.onmessage?.({ data: JSON.stringify({ t: 'rc:file.child.register.ack' }) })
        } else if (msg.t === 'rc:file.child.prepare' && msg.child_id) {
          preparedDirections.push(String(msg.direction ?? ''))
          controlDc.onmessage?.({
            data: JSON.stringify({ t: 'rc:file.child.prepare.ack', child_id: msg.child_id }),
          })
        }
      }

      // Source payload: 120 bytes [0..119], split across 4 stripes (30 bytes each)
      // Receiver grants credit in 12-byte windows with 8-byte chunks to verify strict credit pacing.
      const sourceBytes = new Uint8Array(120)
      for (let i = 0; i < 120; i++) sourceBytes[i] = (i * 7 + 3) & 0xff
      const reassembledTarget = new Uint8Array(120)
      let eofCount = 0
      let expectedSha256 = ''

      let reserveIdx = 0
      ws.sendRaw = (rawMsg: unknown) => {
        const msg = rawMsg as Record<string, unknown>
        sentWs.push(msg)
        if (msg.t === 'rc:file.child.reserve') {
          expect(msg.direction).toBe('upload')
          const cid = CHILD_IDS[reserveIdx++ % CHILD_IDS.length]!
          queueMicrotask(() => {
            deliverRc('rc:file.child.reserved', {
              session_id: SESSION_ID,
              child_id: cid,
              transfer_id: msg.transfer_id,
            })
          })
        } else if (msg.t === 'rc:file.sdp.offer') {
          expect(msg.direction).toBe('upload')
          const cid = String(msg.child_id)
          const childPcIdx = CHILD_IDS.indexOf(cid) + 1
          const childPc = FakePc.instances[childPcIdx]!
          const childFilesDc = childPc.dcs.get('files')!

          let stripeOffset = 0
          let stripeLength = 0
          let stripeReceived = 0
          let allowedBytes = 0
          let transferId = ''
          let stripeId = ''

          childFilesDc.onSend = (raw) => {
            if (typeof raw === 'string') {
              const req = JSON.parse(raw) as {
                t?: string
                id?: string
                stripe_id?: string
                offset?: number
                length?: number
                size?: number
                sha256?: string
              }
              if (req.t === 'files:upload.begin') {
                transferId = String(req.id)
                stripeId = String(req.stripe_id)
                stripeOffset = Number(req.offset)
                stripeLength = Number(req.length)
                expectedSha256 = String(req.sha256)
                // Grant initial 12-byte credit window (chunk_bytes = 8)
                allowedBytes = Math.min(stripeLength, 12)
                queueMicrotask(() => {
                  childFilesDc.onmessage?.({
                    data: JSON.stringify({
                      t: 'files:upload.credit',
                      id: transferId,
                      stripe_id: stripeId,
                      acked_bytes: 0,
                      credit_bytes: allowedBytes,
                      chunk_bytes: 8,
                    }),
                  })
                })
              } else if (req.t === 'files:upload.eof') {
                expect(stripeReceived).toBe(stripeLength)
                eofCount += 1
                if (eofCount < 4) {
                  queueMicrotask(() => {
                    childFilesDc.onmessage?.({
                      data: JSON.stringify({
                        t: 'files:upload.stripe_done',
                        id: transferId,
                        stripe_id: stripeId,
                        bytes: stripeReceived,
                      }),
                    })
                  })
                } else {
                  queueMicrotask(() => {
                    childFilesDc.onmessage?.({
                      data: JSON.stringify({
                        t: 'files:upload.complete',
                        id: transferId,
                        path: '/tmp/uploaded-striped.bin',
                        bytes: 120,
                        sha256: expectedSha256,
                      }),
                    })
                  })
                }
              }
            } else {
              const chunk = new Uint8Array(raw)
              expect(chunk.byteLength).toBeLessThanOrEqual(8)
              expect(stripeReceived + chunk.byteLength).toBeLessThanOrEqual(allowedBytes)
              reassembledTarget.set(chunk, stripeOffset + stripeReceived)
              stripeReceived += chunk.byteLength
              if (stripeReceived === allowedBytes && stripeReceived < stripeLength) {
                const nextCredit = Math.min(12, stripeLength - stripeReceived)
                allowedBytes += nextCredit
                queueMicrotask(() => {
                  childFilesDc.onmessage?.({
                    data: JSON.stringify({
                      t: 'files:upload.credit',
                      id: transferId,
                      stripe_id: stripeId,
                      acked_bytes: stripeReceived,
                      credit_bytes: nextCredit,
                      chunk_bytes: 8,
                    }),
                  })
                })
              }
            }
          }

          queueMicrotask(() => {
            deliverRc('rc:file.sdp.answer', {
              session_id: SESSION_ID,
              child_id: cid,
              sdp: SAMPLE_SDP,
            })
            childFilesDc.onopen?.()
          })
        }
      }

      const file = new File([sourceBytes], 'uploaded-striped.bin', {
        type: 'application/octet-stream',
      })
      const uploadRes = await rc.uploadFile(file, { childConnections: 4 })
      expect(uploadRes).toEqual({ path: '/tmp/uploaded-striped.bin', bytes: 120 })
      expect(Array.from(reassembledTarget)).toEqual(Array.from(sourceBytes))
      expect(preparedDirections).toEqual(['upload', 'upload', 'upload', 'upload'])
      expect(registeredKey).not.toBeNull()

      // Verify all 4 upload child SDP offers carried valid P-256 proofs with direction='upload'
      const childOffers = sentWs.filter((m) => m.t === 'rc:file.sdp.offer')
      expect(childOffers).toHaveLength(4)
      for (const offer of childOffers) {
        const proof = offer.proof as { nonce: string; key: string; sig: string }
        expect(proof.key).toBe(registeredKey)
        const uploadTranscript = fileChildOfferTranscript({
          sessionId: SESSION_ID,
          childId: String(offer.child_id),
          transferId: String(offer.transfer_id),
          direction: 'upload',
          agentId: AGENT_ID,
          controllerUserId: USER_ID,
          offerSdp: String(offer.sdp),
          nonce: proof.nonce,
        })
        expect(uploadTranscript).not.toBeNull()
        expect(await verifyPeerAuth(proof.key, uploadTranscript!, proof.sig)).toBe(true)

        // Proof must NOT validate against a download transcript
        const downloadTranscript = fileChildOfferTranscript({
          sessionId: SESSION_ID,
          childId: String(offer.child_id),
          transferId: String(offer.transfer_id),
          direction: 'download',
          agentId: AGENT_ID,
          controllerUserId: USER_ID,
          offerSdp: String(offer.sdp),
          nonce: proof.nonce,
        })
        expect(await verifyPeerAuth(proof.key, downloadTranscript!, proof.sig)).toBe(false)
      }

      // Now test mid-upload revocation via rc:file.child.revoke:
      reserveIdx = 0
      ws.sendRaw = (rawMsg: unknown) => {
        const msg = rawMsg as Record<string, unknown>
        sentWs.push(msg)
        if (msg.t === 'rc:file.child.reserve') {
          const cid = CHILD_IDS[reserveIdx++ % CHILD_IDS.length]!
          queueMicrotask(() => {
            deliverRc('rc:file.child.reserved', {
              session_id: SESSION_ID,
              child_id: cid,
              transfer_id: msg.transfer_id,
            })
          })
        }
      }

      const inFlightUpload = rc.uploadFile(file, { childConnections: 4 })
      await new Promise((r) => setTimeout(r, 20))
      deliverRc('rc:file.child.revoke', {
        session_id: SESSION_ID,
        reason: 'policy_changed',
      })
      await expect(inFlightUpload).rejects.toThrow(/file child capability revoked/)
      expect(rc.fileChildRevoked.value).toBe(true)
      expect(rc.phase.value).toBe('connected')

      rc.disconnect()
    } finally {
      globalThis.RTCPeerConnection = origPc
      api.get = origApiGet
      ws.onRcMessage = origOnRc
    }
  })

  it('clamps upload children to [0, 8] and download children to [0, 4], and runs 8 upload + 4 download children simultaneously without interference', async () => {
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc

    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) {
        h({ t, ...msg })
      }
    }

    const sentWs: Record<string, unknown>[] = []
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet

    class FakeDc {
      label: string
      readyState = 'open'
      binaryType = 'arraybuffer'
      bufferedAmount = 0
      bufferedAmountLowThreshold = 0
      onopen: (() => void) | null = null
      onclose: (() => void) | null = null
      onmessage: ((ev: { data: string | ArrayBuffer }) => void) | null = null
      sent: Array<string | ArrayBuffer> = []
      closed = false
      constructor(label: string) {
        this.label = label
      }
      send(data: string | ArrayBuffer) {
        this.sent.push(data)
        this.onSend?.(data)
      }
      onSend?: (data: string | ArrayBuffer) => void
      close() {
        this.closed = true
        this.readyState = 'closed'
      }
    }

    class FakePc {
      static instances: FakePc[] = []
      dcs = new Map<string, FakeDc>()
      closed = false
      connectionState = 'connected'
      signalingState: RTCSignalingState = 'stable'
      localDesc: RTCSessionDescriptionInit | null = null
      remoteDesc: RTCSessionDescriptionInit | null = null
      onicecandidate:
        | ((ev: { candidate: { toJSON: () => RTCIceCandidateInit } | null }) => void)
        | null = null
      onconnectionstatechange: (() => void) | null = null
      ontrack: ((ev: unknown) => void) | null = null
      constructor() {
        FakePc.instances.push(this)
      }
      addTransceiver() {}
      createDataChannel(label: string) {
        const dc = new FakeDc(label)
        this.dcs.set(label, dc)
        return dc as unknown as RTCDataChannel
      }
      async createOffer() {
        return { type: 'offer' as const, sdp: SAMPLE_SDP }
      }
      async setLocalDescription(desc: RTCSessionDescriptionInit) {
        this.localDesc = desc
        this.signalingState = 'have-local-offer'
      }
      async setRemoteDescription(desc: RTCSessionDescriptionInit) {
        if (this.signalingState !== 'have-local-offer') {
          throw new Error(`InvalidStateError: setRemoteDescription in ${this.signalingState}`)
        }
        this.remoteDesc = desc
        this.signalingState = 'stable'
      }
      async addIceCandidate() {}
      async getStats() {
        return new Map() as unknown as RTCStatsReport
      }
      close() {
        this.closed = true
        this.connectionState = 'closed'
      }
    }

    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakePc as unknown as typeof RTCPeerConnection

    const writtenDlChunks: Uint8Array[] = []
    const win = window as unknown as {
      showSaveFilePicker?: () => Promise<{
        createWritable: () => Promise<{
          write: (data: ArrayBuffer) => Promise<void>
          close: () => Promise<void>
          abort: (reason?: unknown) => Promise<void>
        }>
      }>
    }
    const origPicker = win.showSaveFilePicker
    win.showSaveFilePicker = async () => ({
      createWritable: async () => ({
        write: async (data: ArrayBuffer) => {
          writtenDlChunks.push(new Uint8Array(data))
        },
        close: async () => {},
        abort: async () => {},
      }),
    })

    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
          files: ['resume'] as ('resume')[],
        },
      })

      // 1. Verify localStorage clamping: upload clamps to [0, 8], download clamps to [0, 4]
      globalThis.localStorage?.setItem('meshharbor-rc-upload-children', '12')
      globalThis.localStorage?.setItem('meshharbor-rc-download-children', '8')
      const rcFromStorage = useRemoteControl(agentRef, {
        userId: () => USER_ID,
      })
      expect(rcFromStorage.concurrentUploadChildren.value).toBe(8)
      expect(rcFromStorage.concurrentDownloadChildren.value).toBe(4)

      rcFromStorage.setConcurrentUploadChildren(9)
      expect(rcFromStorage.concurrentUploadChildren.value).toBe(8)
      expect(globalThis.localStorage?.getItem('meshharbor-rc-upload-children')).toBe('8')
      rcFromStorage.setConcurrentUploadChildren(-2)
      expect(rcFromStorage.concurrentUploadChildren.value).toBe(0)

      rcFromStorage.setConcurrentDownloadChildren(5)
      expect(rcFromStorage.concurrentDownloadChildren.value).toBe(4)
      expect(globalThis.localStorage?.getItem('meshharbor-rc-download-children')).toBe('4')
      rcFromStorage.setConcurrentDownloadChildren(-1)
      expect(rcFromStorage.concurrentDownloadChildren.value).toBe(0)

      // 2. Connect with both upload=8 and download=4 enabled
      const rc = useRemoteControl(agentRef, {
        userId: () => USER_ID,
        childUploadConnections: 9, // clamped to 8
        childDownloadConnections: 5, // clamped to 4
      })
      expect(rc.concurrentUploadChildren.value).toBe(8)
      expect(rc.concurrentDownloadChildren.value).toBe(4)

      await rc.connect(AGENT_ID)
      const sessionReq = sentWs.find((m) => m.t === 'rc:session.request')
      expect(sessionReq).toBeDefined()
      expect(sessionReq!.browser_caps).toContain('file-child-upload')
      expect(sessionReq!.browser_caps).toContain('file-child-download')

      const parentPc = FakePc.instances[0]!
      deliverRc('rc:session.created', {
        session_id: SESSION_ID,
        agent_id: AGENT_ID,
        permissions: 'VIEW | INPUT | CLIPBOARD | FILES',
      })
      deliverRc('rc:ready', { session_id: SESSION_ID })
      await new Promise((r) => setTimeout(r, 10))
      deliverRc('rc:sdp.answer', { session_id: SESSION_ID, sdp: SAMPLE_SDP })
      await new Promise((r) => setTimeout(r, 10))
      parentPc.connectionState = 'connected'
      parentPc.onconnectionstatechange?.()
      expect(rc.phase.value).toBe('connected')

      const controlDc = parentPc.dcs.get('control')!
      let registerCount = 0
      const preparedUploadIds: string[] = []
      const preparedDownloadIds: string[] = []
      controlDc.onSend = (raw) => {
        if (typeof raw !== 'string') return
        const msg = JSON.parse(raw) as {
          t?: string
          key?: string
          child_id?: string
          direction?: string
        }
        if (msg.t === 'rc:file.child.register' && msg.key) {
          registerCount += 1
          controlDc.onmessage?.({ data: JSON.stringify({ t: 'rc:file.child.register.ack' }) })
        } else if (msg.t === 'rc:file.child.prepare' && msg.child_id) {
          if (msg.direction === 'upload') {
            preparedUploadIds.push(msg.child_id)
          } else {
            preparedDownloadIds.push(msg.child_id)
          }
          controlDc.onmessage?.({
            data: JSON.stringify({ t: 'rc:file.child.prepare.ack', child_id: msg.child_id }),
          })
        }
      }

      const upSource = new Uint8Array(160)
      for (let i = 0; i < 160; i++) upSource[i] = (i * 11 + 5) & 0xff
      const upTarget = new Uint8Array(160)
      let upEofCount = 0
      let upExpectedSha = ''

      const dlSource = new Uint8Array(80)
      for (let i = 0; i < 80; i++) dlSource[i] = (i * 19 + 7) & 0xff

      const TWELVE_CHILD_IDS = Array.from({ length: 12 }, (_, i) =>
        `65f0000000000000000002${(i + 1).toString(16).padStart(2, '0')}`,
      )
      const childPcByChildId = new Map<string, FakePc>()
      let reserveCounter = 0

      ws.sendRaw = (rawMsg: unknown) => {
        const msg = rawMsg as Record<string, unknown>
        sentWs.push(msg)
        if (msg.t === 'rc:file.child.reserve') {
          const cid = TWELVE_CHILD_IDS[reserveCounter++]!
          const pcCountBefore = FakePc.instances.length
          queueMicrotask(() => {
            deliverRc('rc:file.child.reserved', {
              session_id: SESSION_ID,
              child_id: cid,
              transfer_id: msg.transfer_id,
              direction: msg.direction,
            })
            queueMicrotask(() => {
              // Capture the newly created FakePc for this childId when offer arrives
              void pcCountBefore
            })
          })
        } else if (msg.t === 'rc:file.sdp.offer') {
          const cid = String(msg.child_id)
          const dir = String(msg.direction)
          // Find the latest FakePc not yet bound to a childId (excluding parentPc at index 0)
          const boundPcs = new Set(childPcByChildId.values())
          const childPc = FakePc.instances.slice(1).find((p) => !boundPcs.has(p))!
          childPcByChildId.set(cid, childPc)
          const childFilesDc = childPc.dcs.get('files')!

          if (dir === 'upload') {
            let stripeOffset = 0
            let stripeLength = 0
            let stripeReceived = 0
            let transferId = ''
            let stripeId = ''

            childFilesDc.onSend = (raw) => {
              if (typeof raw === 'string') {
                const req = JSON.parse(raw) as {
                  t?: string
                  id?: string
                  stripe_id?: string
                  stripe_count?: number
                  offset?: number
                  length?: number
                  sha256?: string
                }
                if (req.t === 'files:upload.begin') {
                  expect(req.stripe_count).toBe(8)
                  transferId = String(req.id)
                  stripeId = String(req.stripe_id)
                  stripeOffset = Number(req.offset)
                  stripeLength = Number(req.length)
                  upExpectedSha = String(req.sha256)
                  queueMicrotask(() => {
                    childFilesDc.onmessage?.({
                      data: JSON.stringify({
                        t: 'files:upload.credit',
                        id: transferId,
                        stripe_id: stripeId,
                        acked_bytes: 0,
                        credit_bytes: stripeLength,
                        chunk_bytes: 16,
                      }),
                    })
                  })
                } else if (req.t === 'files:upload.eof') {
                  expect(stripeReceived).toBe(stripeLength)
                  upEofCount += 1
                  if (upEofCount < 8) {
                    queueMicrotask(() => {
                      childFilesDc.onmessage?.({
                        data: JSON.stringify({
                          t: 'files:upload.stripe_done',
                          id: transferId,
                          stripe_id: stripeId,
                          bytes: stripeReceived,
                        }),
                      })
                    })
                  } else {
                    queueMicrotask(() => {
                      childFilesDc.onmessage?.({
                        data: JSON.stringify({
                          t: 'files:upload.complete',
                          id: transferId,
                          path: '/tmp/up-8.bin',
                          bytes: 160,
                          sha256: upExpectedSha,
                        }),
                      })
                    })
                  }
                }
              } else {
                const chunk = new Uint8Array(raw)
                upTarget.set(chunk, stripeOffset + stripeReceived)
                stripeReceived += chunk.byteLength
              }
            }
          } else {
            childFilesDc.onSend = (raw) => {
              if (typeof raw !== 'string') return
              const req = JSON.parse(raw) as {
                t?: string
                id?: string
                offset?: number
                length?: number
              }
              if (req.t === 'files:get') {
                const off = Number(req.offset ?? 0)
                const len = Number(req.length ?? 0)
                const slice = dlSource.slice(off, off + len)
                queueMicrotask(() => {
                  childFilesDc.onmessage?.({
                    data: JSON.stringify({
                      t: 'files:offer',
                      id: req.id,
                      name: 'dl-4.bin',
                      size: len,
                    }),
                  })
                  childFilesDc.onmessage?.({
                    data: slice.buffer.slice(slice.byteOffset, slice.byteOffset + slice.byteLength),
                  })
                  childFilesDc.onmessage?.({
                    data: JSON.stringify({
                      t: 'files:eof',
                      id: req.id,
                      bytes: len,
                    }),
                  })
                })
              }
            }
          }

          queueMicrotask(() => {
            deliverRc('rc:file.sdp.answer', {
              session_id: SESSION_ID,
              child_id: cid,
              sdp: SAMPLE_SDP,
            })
            childFilesDc.onopen?.()
          })
        }
      }

      // Launch 8-stripe upload (passing 9 -> clamped to 8) and 4-stripe download (passing 5 -> clamped to 4) concurrently!
      const upFile = new File([upSource], 'up-8.bin', { type: 'application/octet-stream' })
      const [upRes, dlRes] = await Promise.all([
        rc.uploadFile(upFile, { childConnections: 9 }),
        rc.downloadFile('/var/data/dl-4.bin', 'dl-4.bin', {
          childConnections: 5,
          sizeHint: 80,
        }),
      ])

      expect(upRes).toEqual({ path: '/tmp/up-8.bin', bytes: 160 })
      expect(dlRes).toEqual({ name: 'dl-4.bin', bytes: 80 })
      expect(Array.from(upTarget)).toEqual(Array.from(upSource))

      const dlReassembled = new Uint8Array(80)
      let dlPos = 0
      for (const c of writtenDlChunks) {
        dlReassembled.set(c, dlPos)
        dlPos += c.byteLength
      }
      expect(Array.from(dlReassembled)).toEqual(Array.from(dlSource))

      // Verify exactly 1 ephemeral key registration shared across both concurrent transfers,
      // 8 upload children (9th rejected by clamp), and 4 download children (5th rejected by clamp)
      expect(registerCount).toBe(1)
      expect(preparedUploadIds).toHaveLength(8)
      expect(preparedDownloadIds).toHaveLength(4)

      // Verify all 12 child PCs were closed cleanly upon completion
      expect(childPcByChildId.size).toBe(12)
      for (const pc of childPcByChildId.values()) {
        expect(pc.closed).toBe(true)
      }

      rc.disconnect()
    } finally {
      globalThis.RTCPeerConnection = origPc
      win.showSaveFilePicker = origPicker
      api.get = origApiGet
      ws.onRcMessage = origOnRc
    }
  })

  it('buffers livePc local ICE candidates until rc:sdp.offer is sent, flushes in order, discards on offer error, resets on reconnect, and preserves empty sessionId handling', async () => {
    // 1. Direct unit verification of createLocalIceOutbox
    const rawOut: Record<string, unknown>[] = []
    const outbox = createLocalIceOutbox((m) => rawOut.push(m))
    expect(outbox.isOfferSent()).toBe(false)
    expect(outbox.pendingCount()).toBe(0)

    // Empty sessionId or null candidate is ignored without buffering or sending
    outbox.onCandidate('', { candidate: 'cand-empty-sid' })
    outbox.onCandidate(null, { candidate: 'cand-null-sid' })
    outbox.onCandidate('sid-1', null)
    expect(outbox.pendingCount()).toBe(0)
    expect(rawOut).toHaveLength(0)

    // Candidates arriving while offerSent=false are queued in order
    outbox.onCandidate('sid-1', { candidate: 'host-udp-192.168.1.42' })
    outbox.onCandidate('sid-1', { candidate: 'host-udp-100.64.0.58' })
    expect(outbox.pendingCount()).toBe(2)
    expect(rawOut).toHaveLength(0)

    // Flushing after ws.sendRaw(offerFrame) emits queued candidates in FIFO order
    rawOut.push({ t: 'rc:sdp.offer', session_id: 'sid-1' })
    outbox.markOfferSentAndFlush('sid-1')
    expect(outbox.isOfferSent()).toBe(true)
    expect(outbox.pendingCount()).toBe(0)
    expect(rawOut.map((m) => [m.t, (m.candidate as RTCIceCandidateInit | undefined)?.candidate])).toEqual([
      ['rc:sdp.offer', undefined],
      ['rc:ice', 'host-udp-192.168.1.42'],
      ['rc:ice', 'host-udp-100.64.0.58'],
    ])

    // Candidates arriving when offerSent=true are sent immediately
    outbox.onCandidate('sid-1', { candidate: 'srflx-udp-198.51.100.8' })
    expect(outbox.pendingCount()).toBe(0)
    expect(rawOut).toHaveLength(4)
    expect(rawOut[3]).toEqual({
      t: 'rc:ice',
      session_id: 'sid-1',
      candidate: { candidate: 'srflx-udp-198.51.100.8' },
    })

    // Reset on error or new reconnect attempt discards buffered candidates and resets offerSent
    outbox.reset()
    expect(outbox.isOfferSent()).toBe(false)
    outbox.onCandidate('sid-2', { candidate: 'stale-before-fail' })
    expect(outbox.pendingCount()).toBe(1)
    outbox.reset()
    expect(outbox.pendingCount()).toBe(0)
    expect(rawOut).toHaveLength(4)

    // 2. End-to-end composable verification across offerAsk async window, offer error, and reconnect
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc

    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) {
        h({ t, ...msg })
      }
    }

    const sentWs: Record<string, unknown>[] = []
    ws.sendRaw = (msg: unknown) => {
      sentWs.push(msg as Record<string, unknown>)
    }

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet

    let shouldThrowOnSetLocal = false
    class FakeRacePc {
      static instances: FakeRacePc[] = []
      closed = false
      connectionState = 'new'
      signalingState: RTCSignalingState = 'stable'
      onicecandidate:
        | ((ev: { candidate: { toJSON: () => RTCIceCandidateInit } | null }) => void)
        | null = null
      onconnectionstatechange: (() => void) | null = null
      ontrack: ((ev: unknown) => void) | null = null
      constructor() {
        FakeRacePc.instances.push(this)
      }
      addTransceiver() {}
      createDataChannel() {
        return {
          readyState: 'open',
          binaryType: 'arraybuffer',
          close() {},
          send() {},
        } as unknown as RTCDataChannel
      }
      async createOffer() {
        return { type: 'offer' as const, sdp: SAMPLE_SDP }
      }
      async setLocalDescription() {
        // Browser gathers local host candidates immediately inside setLocalDescription,
        // BEFORE offerAsk(...) finishes and BEFORE ws.sendRaw(offerFrame) runs!
        this.onicecandidate?.({
          candidate: { toJSON: () => ({ candidate: 'cand-host-1', sdpMid: '0', sdpMLineIndex: 0 }) },
        })
        this.onicecandidate?.({
          candidate: { toJSON: () => ({ candidate: 'cand-host-2', sdpMid: '0', sdpMLineIndex: 0 }) },
        })
        if (shouldThrowOnSetLocal) {
          throw new Error('simulated setLocalDescription failure')
        }
        this.signalingState = 'have-local-offer'
      }
      async setRemoteDescription() {
        this.signalingState = 'stable'
      }
      async addIceCandidate() {}
      async getStats() {
        return new Map() as unknown as RTCStatsReport
      }
      close() {
        this.closed = true
      }
    }

    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakeRacePc as unknown as typeof RTCPeerConnection

    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
        },
      })
      const rc = useRemoteControl(agentRef, { userId: () => USER_ID })

      // Attempt 1: simulated failure in setLocalDescription after 2 candidates fired
      shouldThrowOnSetLocal = true
      await rc.connect(AGENT_ID)
      // Before session_created, sessionId is null -> candidate ignored
      FakeRacePc.instances[0]!.onicecandidate?.({
        candidate: { toJSON: () => ({ candidate: 'cand-no-session-id' }) },
      })
      deliverRc('rc:session.created', { session_id: '65f000000000000000000901', agent_id: AGENT_ID })
      sentWs.length = 0
      deliverRc('rc:ready', { session_id: '65f000000000000000000901' })
      await new Promise((r) => setTimeout(r, 25))
      // Neither rc:sdp.offer nor the 2 buffered rc:ice candidates may be sent on failure
      expect(sentWs.filter((m) => m.t === 'rc:sdp.offer' || m.t === 'rc:ice')).toEqual([])

      // Attempt 2 (reconnect): succeeds; host candidates fire during setLocalDescription (before offerAsk finishes)
      shouldThrowOnSetLocal = false
      await rc.connect(AGENT_ID)
      const sid2 = '65f000000000000000000902'
      deliverRc('rc:session.created', { session_id: sid2, agent_id: AGENT_ID })
      sentWs.length = 0
      deliverRc('rc:ready', { session_id: sid2 })
      await new Promise((r) => setTimeout(r, 30))

      // Late trickle candidate after offerSent=true is sent immediately
      const pc2 = FakeRacePc.instances[FakeRacePc.instances.length - 1]!
      pc2.onicecandidate?.({
        candidate: { toJSON: () => ({ candidate: 'cand-srflx-late', sdpMid: '0', sdpMLineIndex: 0 }) },
      })

      const sigMsgs = sentWs.filter((m) => m.t === 'rc:sdp.offer' || m.t === 'rc:ice')
      expect(
        sigMsgs.map((m) => [m.t, m.session_id, (m.candidate as RTCIceCandidateInit | undefined)?.candidate]),
      ).toEqual([
        ['rc:sdp.offer', sid2, undefined],
        ['rc:ice', sid2, 'cand-host-1'],
        ['rc:ice', sid2, 'cand-host-2'],
        ['rc:ice', sid2, 'cand-srflx-late'],
      ])

      rc.disconnect()
    } finally {
      globalThis.RTCPeerConnection = origPc
      api.get = origApiGet
      ws.onRcMessage = origOnRc
    }
  })

  it('useRemoteControl() channels.control.onopen records dc_open without throwing and emits stored preferences', async () => {
    const { vi } = await import('vitest')
    const { createPinia, setActivePinia } = await import('pinia')
    const { ref } = await import('vue')
    const { useWsStore } = await import('@/stores/ws')
    const { api } = await import('@/api/client')
    const { useRemoteControl } = await import('@/composables/useRemoteControl')

    setActivePinia(createPinia())
    const ws = useWsStore()
    ws.status = 'connected'

    const rcListeners = new Map<string, Set<(msg: Record<string, unknown>) => void>>()
    const origOnRc = ws.onRcMessage
    ws.onRcMessage = ((t: string, h: (msg: Record<string, unknown>) => void) => {
      let s = rcListeners.get(t)
      if (!s) {
        s = new Set()
        rcListeners.set(t, s)
      }
      s.add(h)
      return () => s?.delete(h)
    }) as typeof origOnRc

    const deliverRc = (t: string, msg: Record<string, unknown>) => {
      for (const h of Array.from(rcListeners.get(t) ?? [])) {
        h({ t, ...msg })
      }
    }
    ws.sendRaw = () => {}

    const origApiGet = api.get
    api.get = (async () => ({ ice_servers: [] })) as typeof origApiGet

    interface MockDc {
      label: string
      readyState: RTCDataChannelState
      binaryType: BinaryType
      sent: string[]
      onopen: ((ev: Event) => void) | null
      onclose: ((ev: Event) => void) | null
      onmessage: ((ev: MessageEvent) => void) | null
      close: () => void
      send: (data: string) => void
    }
    const createdChannels = new Map<string, MockDc>()

    class FakeControlDcPc {
      closed = false
      connectionState = 'new'
      signalingState: RTCSignalingState = 'stable'
      onicecandidate: ((ev: unknown) => void) | null = null
      onconnectionstatechange: (() => void) | null = null
      ontrack: ((ev: unknown) => void) | null = null
      addTransceiver() {}
      createDataChannel(label: string) {
        const dc: MockDc = {
          label,
          readyState: 'open',
          binaryType: 'arraybuffer',
          sent: [],
          onopen: null,
          onclose: null,
          onmessage: null,
          close() {
            this.readyState = 'closed'
          },
          send(data: string) {
            this.sent.push(String(data))
          },
        }
        createdChannels.set(label, dc)
        return dc as unknown as RTCDataChannel
      }
      async createOffer() {
        return { type: 'offer' as const, sdp: SAMPLE_SDP }
      }
      async setLocalDescription() {
        this.signalingState = 'have-local-offer'
      }
      async setRemoteDescription() {
        this.signalingState = 'stable'
      }
      async addIceCandidate() {}
      async getStats() {
        return new Map() as unknown as RTCStatsReport
      }
      close() {
        this.closed = true
      }
    }

    const origPc = globalThis.RTCPeerConnection
    globalThis.RTCPeerConnection = FakeControlDcPc as unknown as typeof RTCPeerConnection
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    try {
      const agentRef = ref({
        id: AGENT_ID,
        os: 'linux' as const,
        capabilities: {
          codecs: ['h264'] as ('h264' | 'h265' | 'av1')[],
          hw_encoders: [],
          has_input_permission: true,
          supports_clipboard: true,
          supports_file_transfer: true,
          max_simultaneous_sessions: 4,
          fps_high: true,
        },
      })
      const rc = useRemoteControl(agentRef, { userId: () => USER_ID })
      globalThis.localStorage?.removeItem(RESOLUTION_STORAGE_PREFIX + AGENT_ID)
      expect(rc.resolution.value).toEqual({ mode: 'fit' })
      // Automatic stage sizing updates fit dims without writing localStorage
      rc.setFitDimensions(1256, 720)
      expect(rc.resolution.value).toEqual({ mode: 'fit', width: 1256, height: 720 })
      expect(globalThis.localStorage?.getItem(RESOLUTION_STORAGE_PREFIX + AGENT_ID)).toBeNull()

      rc.setResolution({ mode: 'custom', width: 1280, height: 800 })
      rc.setQuality('high')
      rc.setPriority('sharper')

      await rc.connect(AGENT_ID)
      const sid = '65f000000000000000000903'
      deliverRc('rc:session.created', { session_id: sid, agent_id: AGENT_ID })
      deliverRc('rc:ready', { session_id: sid })

      const controlDc = createdChannels.get('control')
      expect(controlDc).toBeDefined()
      expect(typeof controlDc!.onopen).toBe('function')

      // Must not throw ReferenceError on activeTiming
      expect(() => controlDc!.onopen!(new Event('open'))).not.toThrow()

      const parsedSent = controlDc!.sent.map((raw) => JSON.parse(raw) as Record<string, unknown>)
      expect(parsedSent).toEqual(
        expect.arrayContaining([
          { t: 'rc:quality', quality: 'high' },
          { t: 'rc:resolution', mode: 'custom', width: 1280, height: 800 },
          { t: 'rc:priority', mode: 'sharper' },
        ]),
      )

      // Disconnect emits the connect-timing line; dc_open must be recorded (not 'dc_open:—')
      rc.disconnect()
      const timingLines = warnSpy.mock.calls
        .map((args: unknown[]) => args.map(String).join(' '))
        .filter((line: string) => line.includes('[rc] connect closed'))
      expect(timingLines.length).toBeGreaterThan(0)
      expect(timingLines[timingLines.length - 1]).toMatch(/dc_open:\+\d+\b/)
      expect(timingLines[timingLines.length - 1]).not.toContain('dc_open:—')
    } finally {
      warnSpy.mockRestore()
      globalThis.RTCPeerConnection = origPc
      api.get = origApiGet
      ws.onRcMessage = origOnRc
    }
  })
})

