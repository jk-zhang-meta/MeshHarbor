// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-16 L4 — the frame marker, the browser's half of
 * `agents/meshharbord/src/capture/synthetic_backend.rs` (`marker`), bit for bit.
 *
 * A bench agent paints two markers into every synthetic frame: the frame's
 * own sequence number bottom-left, and the last bench probe it received on
 * the input channel bottom-right. Each is a 12-bit number and a CRC-4,
 * painted as a 2×8 grid of 16×16 blocks (black 0, white 1) inside an 8 px
 * mid-grey quiet margin. That survives 4:2:0, a high QP and a 4× downscale;
 * the CRC turns a misread into a miss, never a wrong number.
 *
 * The Rust module is the reference. Every constant, the sampling inset, the
 * dead band and the margin check are copied, not re-derived, and the unit
 * tests pin the same CRC words the Rust tests pin.
 */

export const BLOCK = 16
export const COLS = 8
export const ROWS = 2
export const MARGIN = 8
/** The grid, without its margin. */
export const GRID_W = BLOCK * COLS
export const GRID_H = BLOCK * ROWS
/** Luma threshold between a 0 block and a 1 block. */
const THRESHOLD = 125
/** A block whose centre averages inside this band around the threshold is
 *  unreadable, not a guess. */
const DEAD_BAND = 40
/** The downscale factors a decoder tries, smallest first. */
export const SCALES = [1, 2, 4] as const
/** Mid-grey (0x80 → luma ≈ 126 after BT.601), within this band. */
const GREY_MIN = 100
const GREY_MAX = 152

export type Corner = 'bottom-left' | 'bottom-right'

/** CRC-4/ITU (x⁴ + x + 1, init 0) over the 12 bits, MSB first. */
export function crc4(seq: number): number {
  let crc = 0
  for (let i = 11; i >= 0; i--) {
    const bit = (seq >> i) & 1
    const top = (crc >> 3) & 1
    crc = (crc << 1) & 0x0f
    if ((top ^ bit) === 1) crc ^= 0x03
  }
  return crc
}

/** The 16-bit word painted: sequence (12 bits) then CRC (4 bits). */
export function word(seq: number): number {
  const s = seq & 0x0fff
  return (s << 4) | crc4(s)
}

type Luma = ArrayLike<number>

/** Read the number from a luma plane's `corner`, trying each downscale
 *  factor in {@link SCALES}. `null` when no factor yields a grid whose every
 *  block is readable and whose CRC matches. */
export function decodeLumaAt(
  corner: Corner,
  y: Luma,
  w: number,
  h: number,
  stride: number,
): number | null {
  for (const k of SCALES) {
    const seq = decodeAtScale(corner, y, w, h, stride, k)
    if (seq !== null) return seq
  }
  return null
}

function decodeAtScale(
  corner: Corner,
  y: Luma,
  w: number,
  h: number,
  stride: number,
  k: number,
): number | null {
  // The marker sits MARGIN in from its side and the bottom of the SOURCE
  // frame; a k× downscale divides every coordinate by k. Every division
  // below is exact for k in SCALES.
  const block = BLOCK / k
  const ox = corner === 'bottom-left' ? MARGIN / k : w - (MARGIN + GRID_W) / k
  const oy = h - (MARGIN + GRID_H) / k
  if (ox < 0 || oy < 0) return null
  if (block < 4 || ox + GRID_W / k > w || oy + GRID_H / k > h) return null
  // The quiet margin anchors the scale: all four strips around the grid must
  // read mid-grey. At a wrong scale at least one lands on the picture or on
  // the grid itself.
  if (!marginIsGrey(y, w, h, stride, ox, oy, k)) return null
  // Sample each block's centre half, away from the edges where the encoder's
  // blocking and chroma bleed live.
  const inset = block / 4
  let bits = 0
  for (let bit = 0; bit < ROWS * COLS; bit++) {
    const bx = ox + (bit % COLS) * block
    const by = oy + Math.floor(bit / COLS) * block
    let sum = 0
    let n = 0
    for (let yy = by + inset; yy < by + block - inset; yy++) {
      const row = yy * stride
      for (let xx = bx + inset; xx < bx + block - inset; xx++) {
        const v = y[row + xx]
        if (v === undefined) return null
        sum += v
        n++
      }
    }
    const mean = Math.floor(sum / Math.max(n, 1))
    if (Math.abs(mean - THRESHOLD) < DEAD_BAND) return null
    bits = (bits << 1) | (mean > THRESHOLD ? 1 : 0)
  }
  const seq = bits >> 4
  return crc4(seq) === (bits & 0x0f) ? seq : null
}

/** Are the centre lines of the four margin strips around the grid grey? */
function marginIsGrey(
  y: Luma,
  w: number,
  h: number,
  stride: number,
  ox: number,
  oy: number,
  k: number,
): boolean {
  const gw = GRID_W / k
  const gh = GRID_H / k
  const d = Math.max(Math.floor(MARGIN / k / 2), 1)
  const left = ox - d
  const right = ox + gw + d - 1
  const top = oy - d
  const bottom = oy + gh + d - 1
  if (left < 0 || top < 0 || right >= w || bottom >= h) return false
  const mean = (pts: Array<[number, number]>): number | null => {
    let sum = 0
    for (const [xx, yy] of pts) {
      const v = y[yy * stride + xx]
      if (v === undefined) return null
      sum += v
    }
    return pts.length > 0 ? Math.floor(sum / pts.length) : null
  }
  const column = (x: number) => Array.from({ length: gh }, (_, i): [number, number] => [x, oy + i])
  const row = (yy: number) => Array.from({ length: gw }, (_, i): [number, number] => [ox + i, yy])
  return [mean(column(left)), mean(column(right)), mean(row(top)), mean(row(bottom))].every(
    (m) => m !== null && m >= GREY_MIN && m <= GREY_MAX,
  )
}

/** The region a sampler copies out of a `w × h` picture whose visible area
 *  starts at (`x0`, `y0`): the bottom-right MARGIN + grid + MARGIN, which
 *  holds the probe grid at every scale in {@link SCALES}. The marker keeps
 *  its offsets from the region's right and bottom edges, so the region
 *  decodes as a picture of its own. `x`/`y` are even, so a 4:2:0 copy
 *  accepts the rect; `null` when the picture is smaller than the region. */
export function probeRegion(
  w: number,
  h: number,
  x0 = 0,
  y0 = 0,
): { x: number; y: number; width: number; height: number } | null {
  const rw = MARGIN + GRID_W + MARGIN
  const rh = MARGIN + GRID_H + MARGIN
  if (w < rw || h < rh) return null
  const right = x0 + w
  const bottom = y0 + h
  const x = (right - rw) & ~1
  const y = (bottom - rh) & ~1
  return { x, y, width: right - x, height: bottom - y }
}

/** Luma from interleaved 8-bit RGBA or BGRA, for a canvas readback or an
 *  RGB VideoFrame. The marker is achromatic, so the weighting barely
 *  matters; full-range BT.601 keeps black, grey and white on the same sides
 *  of the threshold and inside the grey band as limited-range luma does. */
export function lumaFromRgba(
  px: ArrayLike<number>,
  w: number,
  h: number,
  strideBytes: number,
  order: 'rgba' | 'bgra' = 'rgba',
): Uint8Array {
  const out = new Uint8Array(w * h)
  const [ri, bi] = order === 'rgba' ? [0, 2] : [2, 0]
  for (let yy = 0; yy < h; yy++) {
    for (let xx = 0; xx < w; xx++) {
      const i = yy * strideBytes + xx * 4
      out[yy * w + xx] = (77 * (px[i + ri] ?? 0) + 150 * (px[i + 1] ?? 0) + 29 * (px[i + bi] ?? 0)) >> 8
    }
  }
  return out
}
