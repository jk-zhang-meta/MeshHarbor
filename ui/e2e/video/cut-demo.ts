// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * Cut a take from `record-demo.spec.ts` into the README demo: an MP4 and a GIF.
 *
 *   bun e2e/video/cut-demo.ts <take-dir> [out-dir]
 *
 * One segment per device — from the page with the sidebar collapsed, through
 * Connect, the first paint and the switch to fullscreen, to a few seconds of
 * the desktop full screen — joined by short crossfades, a caption on each, and
 * an end card. Nothing inside a segment is cut or sped up: the time from
 * Connect to the first frame is what the viewer sees.
 *
 * Captions come from MESHHARBOR_DEMO_CAPTIONS, one per device, separated by `|`.
 * ffmpeg is the one on PATH, or WSL's when Windows has none.
 */
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

type Frame = { file: string; t: number; bytes: number }
type Mark = { device: string; what: string; t: number }
type Take = { devices: Array<{ name: string; os: string }>; marks: Mark[]; frames: Frame[] }

const TAKE = resolve(process.argv[2] || '')
const OUT = resolve(process.argv[3] || TAKE)
if (!process.argv[2] || !existsSync(join(TAKE, 'take.json'))) {
  console.error('usage: bun e2e/video/cut-demo.ts <take-dir> [out-dir]  (the take dir holds take.json)')
  process.exit(2)
}

/** Seconds of the page shown before Connect — the sidebar is collapsed by then. */
const LEAD_S = 1.2
/** Seconds of the desktop held full screen. */
const HOLD_S = Number(process.env.MESHHARBOR_DEMO_HOLD_S || 5.5)
const XFADE_S = 0.35
const CARD_S = 3.2
const FPS = 30

const take: Take = JSON.parse(readFileSync(join(TAKE, 'take.json'), 'utf8'))
const captions = (process.env.MESHHARBOR_DEMO_CAPTIONS || '').split('|').map((s) => s.trim())

const useWsl = !Bun.which('ffmpeg') && !!Bun.which('wsl')
/** A path on ffmpeg's command line, as the ffmpeg that will read it sees it. */
function argPath(p: string): string {
  if (!useWsl) return p
  return p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d: string) => `/mnt/${d.toLowerCase()}`)
}
/**
 * A path INSIDE the filter graph. The graph's option parser splits on `:`, so a
 * Windows drive colon has to arrive escaped (`C\:/…`); on the command line the
 * same escape would make the path invalid.
 */
function ffPath(p: string): string {
  if (useWsl || process.platform !== 'win32') return argPath(p)
  return p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, '$1\\:')
}
const FONT =
  process.env.MESHHARBOR_DEMO_FONT ||
  (useWsl ? '/mnt/c/Windows/Fonts/segoeuib.ttf' : process.platform === 'win32' ? 'C\\:/Windows/Fonts/segoeuib.ttf' : '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')

const frames = [...take.frames].sort((a, b) => a.t - b.t)
/** `full`: when the viewer entered fullscreen, in the segment's own time (seconds from its start). */
type Seg = { device: string; list: string; dur: number; full: number | null }

/**
 * Regions to blur, per device: MESHHARBOR_DEMO_BLUR is JSON,
 * `[{"device": 0, "phase": "page" | "full", "rect": [x, y, w, h]}, …]`, in pixels of the 1920×1080
 * frame. A desktop's widgets and banners sit at different places in the page and full screen, so
 * each region is given for the phase it applies to: `page` until just after the fullscreen click,
 * `full` from just before it. The two overlap by 0.3 s around the click, because the frame that
 * switches layout lands within a frame or two of the mark and a region blurred one frame late is
 * a region published.
 *
 * ⚠️ A blur is a claim; only reading the RESULT proves it. And whole-frame OCR is not that
 * reading: on 2026-09-30 the cut with NO blur passed the whole-frame privacy gate, because a
 * widget's translucent text over a busy wallpaper and a banner's small grey line never came out of
 * tesseract. What caught them was OCR of each region, cropped and upscaled 3×, at the full frame
 * rate across the fullscreen switch: 109 of 168 crops named the hidden words without the blur,
 * 0 with it. Run that, and run it on the unblurred cut first, so the check is shown able to fail.
 */
type Blur = { device: number; phase: 'page' | 'full'; rect: [number, number, number, number] }
const blurs: Blur[] = JSON.parse(process.env.MESHHARBOR_DEMO_BLUR || '[]')
const EDGE_S = 0.3

writeFileSync(join(TAKE, 'card1.txt'), 'roomler.ai')
writeFileSync(join(TAKE, 'card2.txt'), process.env.MESHHARBOR_DEMO_TAGLINE || 'Open source · self-hostable')
take.devices.forEach((d, i) => writeFileSync(join(TAKE, `cap${i}.txt`), captions[i] || d.name))

/** One segment per device, holding each desktop `holdS` seconds full screen. */
function segments(holdS: number, tag: string): Seg[] {
  return take.devices.map((d, i) => {
    const at = (what: string) => take.marks.find((m) => m.device === d.name && m.what === what)?.t
    const ready = at('ready')
    const full = at('fullscreen')
    const end = at('end')
    if (ready === undefined || end === undefined) throw new Error(`${d.name}: no ready/end mark`)
    const t0 = ready - LEAD_S
    const t1 = Math.min(end, (full ?? end) + holdS)
    // The frame on screen at t0 is the last one swapped at or before it.
    const firstIdx = Math.max(0, frames.findLastIndex((f) => f.t <= t0))
    const inSeg = frames.slice(firstIdx).filter((f) => f.t < t1)
    const lines = ['ffconcat version 1.0']
    let dur = 0
    inSeg.forEach((f, k) => {
      const start = Math.max(f.t, t0)
      const stop = k + 1 < inSeg.length ? inSeg[k + 1].t : t1
      const len = Math.max(0.001, stop - start)
      dur += len
      lines.push(`file 'frames/${f.file}'`, `duration ${len.toFixed(4)}`)
    })
    // The concat demuxer drops the last entry's duration unless it is repeated.
    lines.push(`file 'frames/${inSeg[inSeg.length - 1].file}'`)
    const list = join(TAKE, `${tag}-seg${i}.ffconcat`)
    writeFileSync(list, lines.join('\n') + '\n')
    console.log(`  ${tag} ${i}  ${d.name.padEnd(14)} ${dur.toFixed(2)} s  ${inSeg.length} frames`)
    return { device: d.name, list, dur, full: full === undefined ? null : full - t0 }
  })
}

/** The blur chain for one segment: `[in]` → `[out]`, or a plain rename when nothing is blurred. */
function blurChain(i: number, s: Seg, inLabel: string, outLabel: string): string[] {
  const mine = blurs.filter((b) => b.device === i)
  if (!mine.length) return [`[${inLabel}]null[${outLabel}]`]
  if (s.full === null && mine.some((b) => b.phase === 'full')) {
    throw new Error(`device ${i} has a "full" blur region but never entered fullscreen`)
  }
  const chain: string[] = []
  let cur = inLabel
  mine.forEach((b, k) => {
    const [x, y, w, h] = b.rect
    const from = b.phase === 'page' ? 0 : Math.max(0, (s.full ?? 0) - EDGE_S)
    const to = b.phase === 'page' ? (s.full ?? s.dur) + EDGE_S : s.dur
    const next = k === mine.length - 1 ? outLabel : `b${i}_${k}`
    // ⚠️ boxblur refuses a radius above half the region's shorter side, and the
    // chroma planes are half size. A 34×30 tray icon with the fixed radius of a
    // widget failed the filter graph, and ffmpeg reported only that the encoder
    // "could not open before EOF". On a small region the clamped radius averages
    // the whole region into one flat colour, which is the point.
    const luma = Math.max(1, Math.min(24, Math.floor(Math.min(w, h) / 2) - 1))
    const chroma = Math.max(1, Math.min(12, Math.floor(Math.min(w, h) / 4) - 1))
    chain.push(
      `[${cur}]split[b${i}_${k}m][b${i}_${k}c]`,
      `[b${i}_${k}c]crop=${w}:${h}:${x}:${y},boxblur=luma_radius=${luma}:luma_power=4:chroma_radius=${chroma}:chroma_power=2[b${i}_${k}k]`,
      `[b${i}_${k}m][b${i}_${k}k]overlay=${x}:${y}:enable='between(t,${from.toFixed(3)},${to.toFixed(3)})'[${next}]`,
    )
    cur = next
  })
  return chain
}

// ── filter graph ──────────────────────────────────────────────────────────
function graph(segs: Seg[]): string {
  const caption = (i: number, dur: number) =>
    `drawtext=fontfile='${FONT}':textfile='${ffPath(join(TAKE, `cap${i}.txt`))}':fontsize=40:fontcolor=0xE6F5F2:` +
    `box=1:boxcolor=0x0A201D@0.92:boxborderw=26:x=(w-text_w)/2:y=h-text_h-92:` +
    `enable='between(t,0.3,${Math.min(5.2, dur - 0.4).toFixed(2)})'`
  const g: string[] = []
  segs.forEach((s, i) => {
    g.push(`[${i}:v]fps=${FPS},scale=1920:1080:flags=lanczos,setsar=1,format=yuv420p[r${i}]`)
    g.push(...blurChain(i, s, `r${i}`, `u${i}`))
    g.push(`[u${i}]${caption(i, s.dur)},settb=1/${FPS},setpts=PTS-STARTPTS[s${i}]`)
  })
  g.push(
    `[${segs.length}:v]format=yuv420p,` +
      `drawtext=fontfile='${FONT}':textfile='${ffPath(join(TAKE, 'card1.txt'))}':fontsize=120:fontcolor=0xE6F5F2:x=(w-text_w)/2:y=(h/2)-text_h-10,` +
      `drawtext=fontfile='${FONT}':textfile='${ffPath(join(TAKE, 'card2.txt'))}':fontsize=46:fontcolor=0x80CBC4:x=(w-text_w)/2:y=(h/2)+34,` +
      `settb=1/${FPS},setpts=PTS-STARTPTS[card]`,
  )
  let prev = 's0'
  let offset = 0
  const chain = [...segs.slice(1).map((_, k) => `s${k + 1}`), 'card']
  chain.forEach((next, k) => {
    offset += segs[k].dur - XFADE_S
    const label = k === chain.length - 1 ? 'out' : `x${k}`
    g.push(`[${prev}][${next}]xfade=transition=fade:duration=${XFADE_S}:offset=${offset.toFixed(3)}[${label}]`)
    prev = label
  })
  return g.join(';')
}

// ── encode ────────────────────────────────────────────────────────────────
function ff(args: string[]) {
  const cmd = useWsl ? ['wsl', '-e', 'ffmpeg', ...args] : ['ffmpeg', ...args]
  const r = Bun.spawnSync(cmd, { stdout: 'inherit', stderr: 'inherit' })
  if (r.exitCode !== 0) throw new Error(`ffmpeg failed (${r.exitCode})`)
}
function render(segs: Seg[], out: string, crf: string) {
  const g = graph(segs)
  writeFileSync(`${out}.filter`, g.replace(/;/g, ';\n') + '\n')
  ff([
    '-hide_banner', '-loglevel', 'error', '-y',
    ...segs.flatMap((s) => ['-f', 'concat', '-safe', '0', '-i', argPath(s.list)]),
    '-f', 'lavfi', '-i', `color=c=0x0A201D:s=1920x1080:r=${FPS}:d=${CARD_S}`,
    // Inline, not `-filter_complex_script`: ffmpeg 7.1 removed that option (a
    // current build answers "Unrecognized option"), and an argv element needs
    // no shell quoting. `<out>.filter` keeps a copy to read.
    '-filter_complex', g,
    '-map', '[out]', '-an',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', crf,
    '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
    argPath(out),
  ])
}

const mp4 = join(OUT, 'roomler-demo.mp4')
const gif = join(OUT, 'demo-preview.gif')
render(segments(HOLD_S, 'mp4'), mp4, process.env.MESHHARBOR_DEMO_CRF || '20')

// The GIF gets its own, shorter cut, rendered near-lossless first. A GIF pays
// for every pixel that changes, and a lock screen's wallpaper is often a
// moving aerial, so each second held full screen costs a megabyte or more.
// ⚠️ Ordered (bayer) dithering, not error diffusion: diffusion re-dithers the
// whole frame whenever anything moves, so no frame matches the one before it
// and a 33-second cut came out at 97 MB; bayer maps a still pixel to the same
// output every frame. The light temporal denoise does the same for the
// stream's codec noise.
// In OUT, not TAKE: a second cut of the same take into another folder must not overwrite it.
const gifSrc = join(OUT, 'gif-source.mp4')
render(segments(Number(process.env.MESHHARBOR_DEMO_GIF_HOLD_S || 3.5), 'gif'), gifSrc, '14')
function toGif(width: string, fps: string, out: string) {
  ff([
    '-hide_banner', '-loglevel', 'error', '-y', '-i', argPath(gifSrc),
    '-vf',
    `fps=${fps},scale=${width}:-1:flags=lanczos,` +
      `atadenoise=0a=0.02:0b=0.04:1a=0.02:1b=0.04:2a=0.02:2b=0.04:s=9,` +
      `split[a][b];[a]palettegen=max_colors=256:stats_mode=full[p];` +
      `[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle`,
    argPath(out),
  ])
}
toGif(process.env.MESHHARBOR_DEMO_GIF_WIDTH || '1280', process.env.MESHHARBOR_DEMO_GIF_FPS || '12', gif)

// The blog's copy is smaller on purpose: the docs build refuses any image over
// MAX_IMAGE_BYTES (3 MiB, ui/docs/theme/images.ts), because the site serves
// images as they are. The README has no such limit and keeps the full one.
const blogGif = join(OUT, 'demo-preview-blog.gif')
toGif(process.env.MESHHARBOR_DEMO_BLOG_GIF_WIDTH || '560', process.env.MESHHARBOR_DEMO_BLOG_GIF_FPS || '6', blogGif)

const mb = (p: string) => (statSync(p).size / 1e6).toFixed(1)
console.log(`\n  ${mp4}  ${mb(mp4)} MB\n  ${gif}  ${mb(gif)} MB\n  ${blogGif}  ${mb(blogGif)} MB`)
if (statSync(blogGif).size > 3 * 1024 * 1024) {
  console.error(`\n  ⚠️  ${blogGif} is over the docs build's 3 MiB image limit — lower MESHHARBOR_DEMO_BLOG_GIF_WIDTH or _FPS`)
  process.exit(1)
}
