// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — image dimensions, per format.
 *
 * Each format is built here as the smallest byte sequence that carries its
 * size, so every offset in `images.ts` is exercised against a header whose
 * layout the test states outright. Then the repo's own images are checked
 * against sizes read independently of that code.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { imageSize } from '../theme/images.ts'

const bytes = (...parts: Array<number[] | string>) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p)))
const u32be = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]
const u16be = (n: number) => [(n >>> 8) & 255, n & 255]
const u16le = (n: number) => [n & 255, (n >>> 8) & 255]
const u24le = (n: number) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255]
const u32le = (n: number) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]
const svg = (attrs: string) => new TextEncoder().encode(`<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" ${attrs}><rect/></svg>`)

describe('PNG', () => {
  it('reads the size from IHDR', () => {
    const png = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], u32be(13), 'IHDR', u32be(1400), u32be(788), [8, 6, 0, 0, 0])
    expect(imageSize(png)).toEqual({ width: 1400, height: 788 })
  })

  it('refuses a PNG whose first chunk is not IHDR', () => {
    const png = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], u32be(13), 'tEXt', u32be(1), u32be(1))
    expect(() => imageSize(png)).toThrow(/IHDR/)
  })
})

describe('GIF', () => {
  it('reads the logical screen size, little-endian', () => {
    expect(imageSize(bytes('GIF89a', u16le(640), u16le(360), [0, 0, 0]))).toEqual({ width: 640, height: 360 })
    expect(imageSize(bytes('GIF87a', u16le(1), u16le(2), [0, 0, 0]))).toEqual({ width: 1, height: 2 })
  })
})

describe('JPEG', () => {
  const app0 = [0xff, 0xe0, ...u16be(16), ...'JFIF\0'.split('').map((c) => c.charCodeAt(0)), 1, 1, 0, 0, 1, 0, 1, 0, 0]
  const sof0 = (w: number, h: number) => [0xff, 0xc0, ...u16be(17), 8, ...u16be(h), ...u16be(w), 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]
  const dht = [0xff, 0xc4, ...u16be(5), 0, 0, 0]

  it('walks the segments to the frame header', () => {
    expect(imageSize(bytes([0xff, 0xd8], app0, sof0(1920, 1080)))).toEqual({ width: 1920, height: 1080 })
  })

  it('does not mistake a Huffman table (C4) for a frame header', () => {
    // C4 sits inside the C0–CF range; read as SOF it would yield garbage.
    expect(imageSize(bytes([0xff, 0xd8], app0, dht, sof0(800, 600)))).toEqual({ width: 800, height: 600 })
  })

  it('reads a progressive frame header (C2) too', () => {
    const sof2 = [0xff, 0xc2, ...u16be(17), 8, ...u16be(300), ...u16be(400), 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]
    expect(imageSize(bytes([0xff, 0xd8], sof2))).toEqual({ width: 400, height: 300 })
  })

  it('skips fill bytes between segments', () => {
    expect(imageSize(bytes([0xff, 0xd8, 0xff], app0, sof0(10, 20)))).toEqual({ width: 10, height: 20 })
  })

  it('refuses a JPEG whose scan starts before any frame header', () => {
    const sos = [0xff, 0xda, ...u16be(8), 1, 1, 0, 0, 0x3f, 0]
    expect(() => imageSize(bytes([0xff, 0xd8], app0, sos))).toThrow(/frame header/)
  })
})

describe('WebP', () => {
  const riff = (chunk: string, body: number[]) => bytes('RIFF', u32le(4 + 8 + body.length), 'WEBP', chunk, u32le(body.length), body)

  it('lossy (VP8): 14-bit sizes after the start code', () => {
    const body = [0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, ...u16le(1200), ...u16le(630), 0, 0]
    expect(imageSize(riff('VP8 ', body))).toEqual({ width: 1200, height: 630 })
  })

  it('lossless (VP8L): width-1 and height-1 bit-packed after the signature', () => {
    const packed = (1199 & 0x3fff) | ((629 & 0x3fff) << 14)
    expect(imageSize(riff('VP8L', [0x2f, ...u32le(packed), 0, 0, 0, 0, 0]))).toEqual({ width: 1200, height: 630 })
  })

  it('extended (VP8X): 24-bit canvas size minus one', () => {
    expect(imageSize(riff('VP8X', [0x10, 0, 0, 0, ...u24le(2399), ...u24le(1259)]))).toEqual({ width: 2400, height: 1260 })
  })

  it('refuses an unknown first chunk', () => {
    expect(() => imageSize(riff('ALPH', new Array(20).fill(0)))).toThrow(/ALPH/)
  })
})

describe('SVG', () => {
  it('uses width and height when both are plain lengths', () => {
    expect(imageSize(svg('width="760" height="400px"'))).toEqual({ width: 760, height: 400 })
  })

  it('falls back to the viewBox — what every hero in this repo carries', () => {
    expect(imageSize(svg('viewBox="0 0 760 400"'))).toEqual({ width: 760, height: 400 })
    expect(imageSize(svg("viewBox='0,0,600,540'"))).toEqual({ width: 600, height: 540 })
  })

  it('derives the missing side from the viewBox ratio', () => {
    expect(imageSize(svg('width="380" viewBox="0 0 760 400"'))).toEqual({ width: 380, height: 200 })
  })

  it('treats a percentage as no size at all', () => {
    expect(imageSize(svg('width="100%" height="100%" viewBox="0 0 760 400"'))).toEqual({ width: 760, height: 400 })
  })

  it('does not read `stroke-width` as the width', () => {
    expect(imageSize(svg('stroke-width="3" viewBox="0 0 100 50"'))).toEqual({ width: 100, height: 50 })
  })

  it('refuses an SVG with no size to reserve', () => {
    expect(() => imageSize(svg('class="x"'))).toThrow(/viewBox/)
  })
})

describe('anything else', () => {
  it('is refused, never guessed', () => {
    expect(() => imageSize(bytes('BM', new Array(40).fill(0)))).toThrow(/knows how to size/)
    expect(() => imageSize(new Uint8Array(0))).toThrow()
  })

  it('refuses a zero size', () => {
    expect(() => imageSize(bytes('GIF89a', u16le(0), u16le(10), [0, 0, 0]))).toThrow(/0×10/)
  })
})

describe("the repo's own images", () => {
  const ui = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

  it('size the heroes by their viewBox, not the 960×420 FR-60 hard-coded', () => {
    expect(imageSize(readFileSync(join(ui, 'src/assets/tutorial/remote-desktop.svg')))).toEqual({ width: 760, height: 400 })
    expect(imageSize(readFileSync(join(ui, 'src/assets/tutorial/hero-mesh.svg')))).toEqual({ width: 600, height: 540 })
  })

  it('size the social card as its IHDR says (1280×640, read with node Buffer)', () => {
    expect(imageSize(readFileSync(join(ui, 'docs/assets/social-preview.png')))).toEqual({ width: 1280, height: 640 })
  })

  it('keep the logo lockup at 422×120, which the top bars draw at 113×32', () => {
    expect(imageSize(readFileSync(join(ui, 'src/assets/brand/meshharbor-logo.svg')))).toEqual({ width: 422, height: 120 })
  })

  it('name only icons that exist, at the size the manifest states', () => {
    const manifest = JSON.parse(readFileSync(join(ui, 'public/site.webmanifest'), 'utf8')) as {
      icons: Array<{ src: string; sizes: string }>
    }
    expect(manifest.icons.length).toBeGreaterThan(0)
    for (const icon of manifest.icons) {
      const [width, height] = icon.sizes.split('x').map(Number)
      expect(imageSize(readFileSync(join(ui, 'public', icon.src.split('?')[0])))).toEqual({ width, height })
    }
    expect(imageSize(readFileSync(join(ui, 'public/apple-touch-icon.png')))).toEqual({ width: 180, height: 180 })
  })
})
