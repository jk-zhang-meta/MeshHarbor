// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 P3 — record a meeting in this browser: every video tile composed onto one canvas
// (a screen share large, the cameras beside it), every voice mixed into one track, written by
// `MediaRecorder` as WebM and saved into the room's files.
//
// A file upload is capped at 100 MiB (the API and the front proxy), so a long meeting is saved
// as parts: a new part every PART_MS or before PART_BYTES, the next recorder started before the
// previous one stops, so nothing falls in between.
//
// What it cannot do: record while this tab is in the background at full rate (browsers slow a
// hidden tab's timers to about one per second), or survive this tab closing — the part in
// progress is lost then. Server-side recording would need neither; it is out of FR-126 P3.
import { ref } from 'vue'

export const PART_MS = 8 * 60_000
export const PART_BYTES = 85 * 1024 * 1024
const WIDTH = 1280
const HEIGHT = 720
const FPS = 24

export interface VideoSource {
  key: string
  stream: MediaStream
  label: string
  screen: boolean
}
export interface AudioSource {
  key: string
  stream: MediaStream
}
export interface RecorderOptions {
  videos(): VideoSource[]
  audios(): AudioSource[]
  /** Save one finished part (1-based). */
  savePart(blob: Blob, part: number): Promise<void>
  /** Tell the meeting: on start, every few seconds while recording, and on stop. */
  announce(recording: boolean): void
}

export interface Rect {
  x: number
  y: number
  w: number
  h: number
}

/** The recorder's format, or `null` when this browser cannot record WebM. */
export function pickMimeType(
  supported: (type: string) => boolean = (t) =>
    typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported(t),
): string | null {
  for (const t of ['video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm']) {
    if (supported(t)) return t
  }
  return null
}

/**
 * Where each of `n` tiles goes on a `w`×`h` canvas. With a screen share (`screen` is its index)
 * it takes the left 78 % and the others stack on the right; otherwise a near-square grid.
 */
export function layoutTiles(n: number, screen: number, w = WIDTH, h = HEIGHT): Rect[] {
  if (n <= 0) return []
  if (screen >= 0 && screen < n) {
    const mainW = n === 1 ? w : Math.round(w * 0.78)
    const rects: Rect[] = new Array(n)
    rects[screen] = { x: 0, y: 0, w: mainW, h }
    const others = n - 1
    const sideW = w - mainW
    const tileH = others > 0 ? Math.min(Math.round(h / others), Math.round((sideW * 9) / 16)) : 0
    let i = 0
    for (let k = 0; k < n; k++) {
      if (k === screen) continue
      rects[k] = { x: mainW, y: i * tileH, w: sideW, h: tileH }
      i++
    }
    return rects
  }
  const cols = Math.ceil(Math.sqrt(n))
  const rows = Math.ceil(n / cols)
  const tw = Math.floor(w / cols)
  const th = Math.floor(h / rows)
  return Array.from({ length: n }, (_, k) => ({ x: (k % cols) * tw, y: Math.floor(k / cols) * th, w: tw, h: th }))
}

export function useMeetingRecorder(opts: RecorderOptions) {
  const recording = ref(false)
  const elapsedSec = ref(0)
  const saving = ref(0)
  const error = ref<string | null>(null)

  let mime = ''
  let canvas: HTMLCanvasElement | null = null
  let g: CanvasRenderingContext2D | null = null
  let audioCtx: AudioContext | null = null
  let dest: MediaStreamAudioDestinationNode | null = null
  let mixed: MediaStream | null = null
  let recorder: MediaRecorder | null = null
  let chunks: Blob[] = []
  let bytes = 0
  let partStart = 0
  let startedAt = 0
  let part = 0
  let drawTimer: ReturnType<typeof setInterval> | null = null
  let beat: ReturnType<typeof setInterval> | null = null
  const videoEls = new Map<string, { el: HTMLVideoElement; track: string }>()
  const audioNodes = new Map<string, { node: MediaStreamAudioSourceNode; track: string }>()

  function syncSources(videos: VideoSource[]) {
    const keep = new Set<string>()
    for (const v of videos) {
      const track = v.stream.getVideoTracks()[0]?.id ?? ''
      keep.add(v.key)
      const have = videoEls.get(v.key)
      if (have && have.track === track) continue
      const el = have?.el ?? document.createElement('video')
      el.muted = true
      el.playsInline = true
      el.srcObject = v.stream
      void el.play().catch(() => {})
      videoEls.set(v.key, { el, track })
    }
    for (const [k, v] of videoEls) {
      if (!keep.has(k)) {
        v.el.srcObject = null
        videoEls.delete(k)
      }
    }
    if (!audioCtx || !dest) return
    const keepA = new Set<string>()
    for (const a of opts.audios()) {
      const track = a.stream.getAudioTracks()[0]?.id
      if (!track) continue
      keepA.add(a.key)
      const have = audioNodes.get(a.key)
      if (have && have.track === track) continue
      have?.node.disconnect()
      const node = audioCtx.createMediaStreamSource(new MediaStream(a.stream.getAudioTracks()))
      node.connect(dest)
      audioNodes.set(a.key, { node, track })
    }
    for (const [k, a] of audioNodes) {
      if (!keepA.has(k)) {
        a.node.disconnect()
        audioNodes.delete(k)
      }
    }
  }

  function draw() {
    if (!g) return
    const videos = opts.videos()
    syncSources(videos)
    g.fillStyle = '#111'
    g.fillRect(0, 0, WIDTH, HEIGHT)
    const rects = layoutTiles(videos.length, videos.findIndex((v) => v.screen))
    videos.forEach((v, i) => {
      const r = rects[i]
      const el = videoEls.get(v.key)?.el
      if (!r || !el || r.w <= 0 || r.h <= 0) return
      const vw = el.videoWidth
      const vh = el.videoHeight
      if (vw > 0 && vh > 0) {
        const s = Math.min(r.w / vw, r.h / vh)
        const dw = vw * s
        const dh = vh * s
        g!.drawImage(el, r.x + (r.w - dw) / 2, r.y + (r.h - dh) / 2, dw, dh)
      }
      g!.fillStyle = 'rgba(0,0,0,0.55)'
      g!.fillRect(r.x + 6, r.y + r.h - 28, Math.min(r.w - 12, 12 + v.label.length * 9), 22)
      g!.fillStyle = '#fff'
      g!.font = '14px sans-serif'
      g!.fillText(v.label, r.x + 12, r.y + r.h - 12, r.w - 24)
    })
    elapsedSec.value = Math.floor((Date.now() - startedAt) / 1000)
    if (Date.now() - partStart >= PART_MS || bytes >= PART_BYTES) void rotate()
  }

  function newRecorder() {
    const r = new MediaRecorder(mixed!, {
      mimeType: mime,
      videoBitsPerSecond: 1_100_000,
      audioBitsPerSecond: 64_000,
    })
    const mine: Blob[] = []
    chunks = mine
    bytes = 0
    partStart = Date.now()
    r.ondataavailable = (e) => {
      if (e.data.size > 0) {
        mine.push(e.data)
        if (chunks === mine) bytes += e.data.size
      }
    }
    r.start(1000)
    recorder = r
  }

  /** Stop `r` and save what it wrote as the next part. */
  async function finish(r: MediaRecorder, data: Blob[]) {
    const stopped = new Promise<void>((resolve) => {
      r.onstop = () => resolve()
    })
    r.stop()
    await stopped
    const n = ++part
    if (data.length === 0) return
    saving.value++
    try {
      await opts.savePart(new Blob(data, { type: 'video/webm' }), n)
    } catch (e) {
      error.value = (e as Error)?.message || String(e)
    } finally {
      saving.value--
    }
  }

  let rotating = false
  async function rotate() {
    if (rotating || !recorder) return
    rotating = true
    const old = recorder
    const oldChunks = chunks
    newRecorder()
    try {
      await finish(old, oldChunks)
    } finally {
      rotating = false
    }
  }

  async function start() {
    if (recording.value) return
    const m = pickMimeType()
    if (!m) throw new Error('This browser cannot record WebM')
    mime = m
    error.value = null
    canvas = document.createElement('canvas')
    canvas.width = WIDTH
    canvas.height = HEIGHT
    g = canvas.getContext('2d')
    audioCtx = new AudioContext()
    dest = audioCtx.createMediaStreamDestination()
    syncSources(opts.videos())
    mixed = new MediaStream([...canvas.captureStream(FPS).getVideoTracks(), ...dest.stream.getAudioTracks()])
    part = 0
    startedAt = Date.now()
    newRecorder()
    drawTimer = setInterval(draw, 1000 / FPS)
    recording.value = true
    opts.announce(true)
    beat = setInterval(() => opts.announce(true), 10_000)
  }

  async function stop() {
    if (!recording.value) return
    recording.value = false
    if (drawTimer) clearInterval(drawTimer)
    if (beat) clearInterval(beat)
    drawTimer = null
    beat = null
    opts.announce(false)
    const last = recorder
    recorder = null
    if (last) await finish(last, chunks)
    mixed?.getTracks().forEach((t) => t.stop())
    for (const v of videoEls.values()) v.el.srcObject = null
    videoEls.clear()
    for (const a of audioNodes.values()) a.node.disconnect()
    audioNodes.clear()
    await audioCtx?.close().catch(() => {})
    audioCtx = null
    dest = null
    mixed = null
    g = null
    canvas = null
  }

  return { recording, elapsedSec, saving, error, start, stop }
}
