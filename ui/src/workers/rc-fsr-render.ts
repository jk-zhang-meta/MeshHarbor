// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/// <reference lib="webworker" />
// P7 (Parsec-class plan, 2026-08-20) — FSR sharpening upscale for the DC
// video workers.
//
// WHY: the agent's resolution rungs (Priority=Smoother caps the encode at a
// 1024 long edge; Balanced relays cap at 1280) ship genuinely fewer pixels,
// and the viewer's only upscale back to the window was CSS bilinear
// (`width/height:100%` + `image-rendering: high-quality`) — remote text at
// 1024×640 on a ~2.5× window reads as mush. This module adds the
// Moonlight-proven fix: AMD FidelityFX Super Resolution 1.0 (EASU edge-
// adaptive upscale + RCAS contrast-adaptive sharpen) as WebGL2 fragment
// passes, run INSIDE the worker between decode and the visible canvas.
//
// Architecture — indirect rendering: the renderer owns a private scratch
// OffscreenCanvas + WebGL2 context; each frame is uploaded with
// texImage2D(VideoFrame) (YUV→RGB stays on-GPU in Chrome), EASU→RCAS render
// into the scratch backbuffer, and the worker finishes with a plain
// `ctx.drawImage(renderer.canvas, …)` onto the EXISTING 2D visible canvas.
// A canvas is locked to its first context type forever, so putting GL on
// the visible canvas would force a main-thread re-mount on every toggle or
// context loss; indirect keeps 'off' and every failure mode byte-identical
// to the shipping 2D path, at the cost of one GPU blit (measured by the
// existing `paint` HopStats).
//
// FSR1 runs on perceptual (gamma) RGBA8 by design — no sRGB/linear plumbing.
//
// ─────────────────────────────────────────────────────────────────────────
// Portions of this file are a GLSL port of AMD FidelityFX Super Resolution
// 1.0 (EASU + RCAS), from ffx_fsr1.h:
//   Copyright (c) 2021 Advanced Micro Devices, Inc. All rights reserved.
//   Licensed under the MIT License.
// Port lineage: shadertoy.com/view/stXSWB (goingdigital, MIT) and
// github.com/Hajime-san/web-fsr (MIT), adapted for OffscreenCanvas workers
// (WebGL2/ES 3.0 has no textureGather, hence the discrete 12-tap loads).
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions: the above copyright notice and this permission
// notice shall be included in all copies or substantial portions of the
// Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
// KIND, EXPRESS OR IMPLIED.
// ─────────────────────────────────────────────────────────────────────────

export type SharpenMode = 'auto' | 'on' | 'off'
export type RenderPass = 'blit' | 'rcas' | 'easu-rcas'

export interface RenderTarget {
  w: number
  h: number
  scale: number
  pass: RenderPass
}

/** EASU's quality zone ends at 2× per axis (AMD guidance); beyond it the
 *  output goes soft and fill cost grows quadratically. CSS finishes any
 *  residual factor from an already-sharpened base. */
export const FSR_MAX_SCALE = 2.0
/** Memory/fill bound — under every desktop GL MAX_TEXTURE_SIZE, and turns
 *  "4K decoded in a huge window" into rcas-only instead of a 40 MB+ FBO. */
export const FSR_MAX_AXIS = 4096
/** Below this upscale factor EASU adds nothing over the compositor —
 *  sharpen only. */
export const RCAS_ONLY_MAX_SCALE = 1.05
/** RCAS sharpness in AMD "stops" (0.0 = maximum sharpening). 0.25 is
 *  near-max crispness without ringing on hard text edges. */
export const DEFAULT_RCAS_SHARPNESS = 0.25

/** localStorage `meshharbor-rc-sharpen` → mode. FR-26 defaulted this to **'on'**
 *  (always-sharpen for crisp 1:1 text), but 'on' runs RCAS on the
 *  `needScale <= 1` path (`computeRenderTarget`) which — as the comment there
 *  says — "invites shimmer": RCAS amplifies the encoder's per-frame
 *  quantisation drift on a static, high-contrast frame, so the picture pulses
 *  blurry↔crisp even with NOTHING moving. Field 2026-08-31: constant
 *  blur/crystallize on static Excel-like cells from one viewer's browser
 *  across two native-res (1080p direct) hosts. Reverted the default to
 *  **'auto'** — sharpen ONLY when actually upscaling (a downscaled/relay
 *  stream, RCAS's intended "crisp text at low resolution" case), never at
 *  1:1. 'on'/'off' stay selectable for operators who want always-on RCAS. */
export function normalizeSharpenMode(v: unknown): SharpenMode {
  return v === 'on' || v === 'off' || v === 'auto' ? v : 'auto'
}

/** localStorage `meshharbor-rc-fsr-sharpness` → RCAS stops, clamped 0..2. */
export function normalizeSharpness(v: unknown): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number.parseFloat(v) : Number.NaN
  if (!Number.isFinite(n)) return DEFAULT_RCAS_SHARPNESS
  return Math.min(2, Math.max(0, n))
}

/**
 * The sizing policy — pure, unit-tested. Decides the visible-canvas backing
 * size and which shader pass to run, from the decoded frame size, the
 * canvas element's CSS box, and devicePixelRatio.
 *
 * `min(cssW·dpr/decodedW, cssH·dpr/decodedH)` IS the `object-fit: contain`
 * fit factor, so letterboxing in adaptive mode is inherently respected; the
 * original/custom scale modes size the element to the decoded aspect
 * already, making contain == fill there. Both target axes derive from ONE
 * scale factor so the backing aspect stays within 1/decodedW of the decoded
 * aspect — the letterbox/cursor math on the main thread keys off the
 * decoded (`first-frame`) dims and must keep agreeing with the compositor.
 */
export function computeRenderTarget(
  decodedW: number,
  decodedH: number,
  cssW: number,
  cssH: number,
  dpr: number,
  mode: SharpenMode,
): RenderTarget {
  const blit: RenderTarget = { w: decodedW, h: decodedH, scale: 1, pass: 'blit' }
  if (
    mode === 'off' ||
    !Number.isFinite(decodedW) ||
    !Number.isFinite(decodedH) ||
    decodedW <= 0 ||
    decodedH <= 0
  ) {
    return blit
  }
  if (!Number.isFinite(cssW) || !Number.isFinite(cssH) || cssW <= 0 || cssH <= 0) {
    // No viewport report yet (synthetic-canvas phase included) — today's path.
    return blit
  }
  const dprC = Number.isFinite(dpr) ? Math.min(4, Math.max(1, dpr)) : 1
  const needScale = Math.min((cssW * dprC) / decodedW, (cssH * dprC) / decodedH)
  if (needScale <= 1) {
    // Stream is LARGER than the window: sharpening before a downscale
    // invites shimmer — 'auto' stays on the 2D path ('on' = explicit user
    // intent, Moonlight-style always-sharpen at decoded size).
    return mode === 'on' ? { w: decodedW, h: decodedH, scale: 1, pass: 'rcas' } : blit
  }
  const s = Math.min(needScale, FSR_MAX_SCALE, FSR_MAX_AXIS / decodedW, FSR_MAX_AXIS / decodedH)
  if (s <= RCAS_ONLY_MAX_SCALE) {
    return { w: decodedW, h: decodedH, scale: 1, pass: 'rcas' }
  }
  return {
    w: Math.round(decodedW * s),
    h: Math.round(decodedH * s),
    scale: s,
    pass: 'easu-rcas',
  }
}

/**
 * FsrEasuCon (ffx_fsr1.h) — the four vec4 uniform constants for EASU,
 * computed once per (input, output) size pair. Input viewport == input size
 * here (WebCodecs hands us the visible rect).
 */
export function easuConstants(inW: number, inH: number, outW: number, outH: number): Float32Array {
  const c = new Float32Array(16)
  // con0 — output pixel → input pixel mapping.
  c[0] = inW / outW
  c[1] = inH / outH
  c[2] = 0.5 * (inW / outW) - 0.5
  c[3] = 0.5 * (inH / outH) - 0.5
  // con1 — texel-size steps for the 12-tap neighbourhood.
  c[4] = 1 / inW
  c[5] = 1 / inH
  c[6] = 1 / inW
  c[7] = -1 / inH
  // con2
  c[8] = -1 / inW
  c[9] = 2 / inH
  c[10] = 1 / inW
  c[11] = 2 / inH
  // con3
  c[12] = 0
  c[13] = 4 / inH
  c[14] = 0
  c[15] = 0
  return c
}

// Fullscreen triangle from gl_VertexID — no vertex buffers.
const VERT_SRC = `#version 300 es
void main() {
  vec2 pos = vec2(gl_VertexID == 1 ? 3.0 : -1.0, gl_VertexID == 2 ? 3.0 : -1.0);
  gl_Position = vec4(pos, 0.0, 1.0);
}
`

// EASU pass: srcTex (texel row 0 = image top) → FBO (texel row r = image
// row r; the Y-flip happens once, in the RCAS/present pass). 12 discrete
// taps (ES 3.0 has no textureGather).
const EASU_FRAG_SRC = `#version 300 es
precision highp float;
uniform sampler2D uSrc;
uniform vec4 uCon0;
uniform vec4 uCon1;
uniform vec4 uCon2;
uniform vec4 uCon3;
out vec4 oColor;

vec3 easuCF(vec2 p) { return textureLod(uSrc, p, 0.0).rgb; }

// Filtering for a given tap for the scalar.
void easuTapF(
  inout vec3 aC, inout float aW, vec2 off, vec2 dir, vec2 len, float lob, float clp, vec3 c
) {
  // Rotate offset by direction, anisotropy.
  vec2 v = vec2(dot(off, dir), dot(off, vec2(-dir.y, dir.x)));
  v *= len;
  float d2 = min(dot(v, v), clp);
  // Windowed lanczos-ish: (25/16 * (2/5 * x^2 - 1)^2 - (25/16 - 1)) * (1/4 * x^2 - 1)^2
  float wB = 0.4 * d2 - 1.0;
  float wA = lob * d2 - 1.0;
  wB *= wB;
  wA *= wA;
  wB = 1.5625 * wB - 0.5625;
  float w = wB * wA;
  aC += c * w;
  aW += w;
}

// Accumulate direction and length for one quad of the bilinear footprint.
void easuSetF(
  inout vec2 dir, inout float len, vec2 pp,
  bool biS, bool biT, bool biU, bool biV,
  float lA, float lB, float lC, float lD, float lE
) {
  float w = 0.0;
  if (biS) w = (1.0 - pp.x) * (1.0 - pp.y);
  if (biT) w = pp.x * (1.0 - pp.y);
  if (biU) w = (1.0 - pp.x) * pp.y;
  if (biV) w = pp.x * pp.y;
  float dc = lD - lC;
  float cb = lC - lB;
  float lenX = max(abs(dc), abs(cb));
  lenX = 1.0 / max(lenX, 0.000030517578125);
  float dirX = lD - lB;
  dir.x += dirX * w;
  lenX = clamp(abs(dirX) * lenX, 0.0, 1.0);
  lenX *= lenX;
  len += lenX * w;
  float ec = lE - lC;
  float ca = lC - lA;
  float lenY = max(abs(ec), abs(ca));
  lenY = 1.0 / max(lenY, 0.000030517578125);
  float dirY = lE - lA;
  dir.y += dirY * w;
  lenY = clamp(abs(dirY) * lenY, 0.0, 1.0);
  lenY *= lenY;
  len += lenY * w;
}

vec3 easuF(vec2 ip) {
  // Input pixel/subpixel under this output pixel.
  vec2 pp = ip * uCon0.xy + uCon0.zw;
  vec2 fp = floor(pp);
  pp -= fp;
  // 12-tap kernel:
  //    b c
  //  e f g h
  //  i j k l
  //    n o
  vec2 p0 = fp * uCon1.xy + uCon1.zw;
  vec2 p1 = p0 + uCon2.xy;
  vec2 p2 = p0 + uCon2.zw;
  vec2 p3 = p0 + uCon3.xy;
  vec4 off = vec4(-0.5, 0.5, -0.5, 0.5) * uCon1.xxyy;
  vec3 bC = easuCF(p0 + off.xw); float bL = bC.g + 0.5 * (bC.r + bC.b);
  vec3 cC = easuCF(p0 + off.yw); float cL = cC.g + 0.5 * (cC.r + cC.b);
  vec3 iC = easuCF(p1 + off.xw); float iL = iC.g + 0.5 * (iC.r + iC.b);
  vec3 jC = easuCF(p1 + off.yw); float jL = jC.g + 0.5 * (jC.r + jC.b);
  vec3 fC = easuCF(p1 + off.yz); float fL = fC.g + 0.5 * (fC.r + fC.b);
  vec3 eC = easuCF(p1 + off.xz); float eL = eC.g + 0.5 * (eC.r + eC.b);
  vec3 kC = easuCF(p2 + off.xw); float kL = kC.g + 0.5 * (kC.r + kC.b);
  vec3 lC_ = easuCF(p2 + off.yw); float lL = lC_.g + 0.5 * (lC_.r + lC_.b);
  vec3 hC = easuCF(p2 + off.yz); float hL = hC.g + 0.5 * (hC.r + hC.b);
  vec3 gC = easuCF(p2 + off.xz); float gL = gC.g + 0.5 * (gC.r + gC.b);
  vec3 oC = easuCF(p3 + off.yz); float oL = oC.g + 0.5 * (oC.r + oC.b);
  vec3 nC = easuCF(p3 + off.xz); float nL = nC.g + 0.5 * (nC.r + nC.b);
  // Edge direction + length from the four bilinear quads.
  vec2 dir = vec2(0.0);
  float len = 0.0;
  easuSetF(dir, len, pp, true, false, false, false, bL, eL, fL, gL, jL);
  easuSetF(dir, len, pp, false, true, false, false, cL, fL, gL, hL, kL);
  easuSetF(dir, len, pp, false, false, true, false, fL, iL, jL, kL, nL);
  easuSetF(dir, len, pp, false, false, false, true, gL, jL, kL, lL, oL);
  vec2 dir2 = dir * dir;
  float dirR = dir2.x + dir2.y;
  bool zro = dirR < 0.000030517578125;
  dirR = inversesqrt(max(dirR, 0.000030517578125));
  dirR = zro ? 1.0 : dirR;
  dir.x = zro ? 1.0 : dir.x;
  dir *= vec2(dirR);
  len = len * 0.5;
  len *= len;
  float stretch = dot(dir, dir) / max(max(abs(dir.x), abs(dir.y)), 0.000030517578125);
  vec2 len2 = vec2(1.0 + (stretch - 1.0) * len, 1.0 - 0.5 * len);
  float lob = 0.5 + ((1.0 / 4.0 - 0.04) - 0.5) * len;
  float clp = 1.0 / max(lob, 0.000030517578125);
  // Dering window = the inner 2×2 quad.
  vec3 min4 = min(min(fC, gC), min(jC, kC));
  vec3 max4 = max(max(fC, gC), max(jC, kC));
  vec3 aC = vec3(0.0);
  float aW = 0.0;
  easuTapF(aC, aW, vec2(0.0, -1.0) - pp, dir, len2, lob, clp, bC);
  easuTapF(aC, aW, vec2(1.0, -1.0) - pp, dir, len2, lob, clp, cC);
  easuTapF(aC, aW, vec2(-1.0, 1.0) - pp, dir, len2, lob, clp, iC);
  easuTapF(aC, aW, vec2(0.0, 1.0) - pp, dir, len2, lob, clp, jC);
  easuTapF(aC, aW, vec2(0.0, 0.0) - pp, dir, len2, lob, clp, fC);
  easuTapF(aC, aW, vec2(-1.0, 0.0) - pp, dir, len2, lob, clp, eC);
  easuTapF(aC, aW, vec2(1.0, 1.0) - pp, dir, len2, lob, clp, kC);
  easuTapF(aC, aW, vec2(2.0, 1.0) - pp, dir, len2, lob, clp, lC_);
  easuTapF(aC, aW, vec2(2.0, 0.0) - pp, dir, len2, lob, clp, hC);
  easuTapF(aC, aW, vec2(1.0, 0.0) - pp, dir, len2, lob, clp, gC);
  easuTapF(aC, aW, vec2(1.0, 2.0) - pp, dir, len2, lob, clp, oC);
  easuTapF(aC, aW, vec2(0.0, 2.0) - pp, dir, len2, lob, clp, nC);
  return min(max4, max(min4, aC / max(aW, 0.000030517578125)));
}

void main() {
  // FBO texel row r = image row r (srcTex row 0 = image top; no flip here —
  // the present pass flips once).
  oColor = vec4(easuF(floor(gl_FragCoord.xy)), 1.0);
}
`

// RCAS pass (+ present flip): input texture rows are image rows; the
// backbuffer row 0 is PRESENTED at the canvas bottom, so read image row
// (uOutH - 1 - fragRow). Non-denoise variant (desktop content, not camera
// noise). texelFetch offsets clamped at the image border.
const RCAS_FRAG_SRC = `#version 300 es
precision highp float;
uniform sampler2D uSrc;
uniform ivec2 uSize;    // input texture size (== output size)
uniform float uRcasCon; // exp2(-sharpness)
out vec4 oColor;

const float FSR_RCAS_LIMIT = 0.25 - 1.0 / 16.0;

vec3 fetchClamped(ivec2 p) {
  return texelFetch(uSrc, clamp(p, ivec2(0), uSize - 1), 0).rgb;
}

void main() {
  ivec2 frag = ivec2(gl_FragCoord.xy);
  ivec2 ip = ivec2(frag.x, uSize.y - 1 - frag.y); // present flip
  //   b
  // d e f
  //   h
  vec3 b = fetchClamped(ip + ivec2(0, -1));
  vec3 d = fetchClamped(ip + ivec2(-1, 0));
  vec3 e = fetchClamped(ip);
  vec3 f = fetchClamped(ip + ivec2(1, 0));
  vec3 h = fetchClamped(ip + ivec2(0, 1));
  // Per-channel min/max of the cross ring.
  vec3 mn4 = min(min(b, d), min(f, h));
  vec3 mx4 = max(max(b, d), max(f, h));
  // Smooth-minimum distance to signal limit (peak {1, -4}).
  vec3 hitMin = mn4 / (4.0 * max(mx4, vec3(0.000030517578125)));
  vec3 hitMax = (vec3(1.0) - mx4) / (4.0 * mn4 - vec3(4.0));
  vec3 lobeRGB = max(-hitMin, hitMax);
  float lobe = max(
    -FSR_RCAS_LIMIT,
    min(max(lobeRGB.r, max(lobeRGB.g, lobeRGB.b)), 0.0)
  ) * uRcasCon;
  float rcpL = 1.0 / (4.0 * lobe + 1.0);
  oColor = vec4((lobe * (b + d + f + h) + e) * rcpL, 1.0);
}
`

function compileProgram(
  gl: WebGL2RenderingContext,
  vertSrc: string,
  fragSrc: string,
): WebGLProgram | null {
  const compile = (type: number, src: string): WebGLShader | null => {
    const sh = gl.createShader(type)
    if (!sh) return null
    gl.shaderSource(sh, src)
    gl.compileShader(sh)
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS) && !gl.isContextLost()) {
      console.warn('[rc-fsr] shader compile failed:', gl.getShaderInfoLog(sh))
      gl.deleteShader(sh)
      return null
    }
    return sh
  }
  const vs = compile(gl.VERTEX_SHADER, vertSrc)
  const fs = compile(gl.FRAGMENT_SHADER, fragSrc)
  if (!vs || !fs) return null
  const prog = gl.createProgram()
  if (!prog) return null
  gl.attachShader(prog, vs)
  gl.attachShader(prog, fs)
  gl.linkProgram(prog)
  gl.deleteShader(vs)
  gl.deleteShader(fs)
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS) && !gl.isContextLost()) {
    console.warn('[rc-fsr] program link failed:', gl.getProgramInfoLog(prog))
    gl.deleteProgram(prog)
    return null
  }
  return prog
}

function makeTexture(gl: WebGL2RenderingContext): WebGLTexture | null {
  const tex = gl.createTexture()
  if (!tex) return null
  gl.bindTexture(gl.TEXTURE_2D, tex)
  // NEAREST: every EASU sample lands on an exact texel centre (the gather
  // emulation offsets), so NEAREST == LINEAR minus the precision bleed.
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
  return tex
}

interface EasuUniforms {
  src: WebGLUniformLocation | null
  con0: WebGLUniformLocation | null
  con1: WebGLUniformLocation | null
  con2: WebGLUniformLocation | null
  con3: WebGLUniformLocation | null
}

interface RcasUniforms {
  src: WebGLUniformLocation | null
  size: WebGLUniformLocation | null
  rcasCon: WebGLUniformLocation | null
}

/**
 * The WebGL2 FSR renderer. `create()` returns null when WebGL2 or the
 * shaders are unavailable — callers fall back to the 2D path. `render()`
 * returns the scratch canvas to drawImage from, or null on a lost context
 * (fall back for THAT frame; the pipeline lazily rebuilds on restore).
 */
export class FsrRenderer {
  readonly canvas: OffscreenCanvas
  private readonly gl: WebGL2RenderingContext
  private readonly progEasu: WebGLProgram
  private readonly progRcas: WebGLProgram
  private readonly uEasu: EasuUniforms
  private readonly uRcas: RcasUniforms
  private readonly srcTex: WebGLTexture
  private readonly fboTex: WebGLTexture
  private readonly fbo: WebGLFramebuffer
  private srcW = 0
  private srcH = 0
  private fboW = 0
  private fboH = 0
  private easuConsDirty = true

  private constructor(
    canvas: OffscreenCanvas,
    gl: WebGL2RenderingContext,
    progEasu: WebGLProgram,
    progRcas: WebGLProgram,
    srcTex: WebGLTexture,
    fboTex: WebGLTexture,
    fbo: WebGLFramebuffer,
  ) {
    this.canvas = canvas
    this.gl = gl
    this.progEasu = progEasu
    this.progRcas = progRcas
    this.srcTex = srcTex
    this.fboTex = fboTex
    this.fbo = fbo
    this.uEasu = {
      src: gl.getUniformLocation(progEasu, 'uSrc'),
      con0: gl.getUniformLocation(progEasu, 'uCon0'),
      con1: gl.getUniformLocation(progEasu, 'uCon1'),
      con2: gl.getUniformLocation(progEasu, 'uCon2'),
      con3: gl.getUniformLocation(progEasu, 'uCon3'),
    }
    this.uRcas = {
      src: gl.getUniformLocation(progRcas, 'uSrc'),
      size: gl.getUniformLocation(progRcas, 'uSize'),
      rcasCon: gl.getUniformLocation(progRcas, 'uRcasCon'),
    }
  }

  static create(): FsrRenderer | null {
    let canvas: OffscreenCanvas
    try {
      canvas = new OffscreenCanvas(2, 2)
    } catch {
      return null
    }
    const gl = canvas.getContext('webgl2', {
      alpha: false,
      antialias: false,
      depth: false,
      stencil: false,
      preserveDrawingBuffer: false,
    }) as WebGL2RenderingContext | null
    if (!gl) return null
    const progEasu = compileProgram(gl, VERT_SRC, EASU_FRAG_SRC)
    const progRcas = compileProgram(gl, VERT_SRC, RCAS_FRAG_SRC)
    const srcTex = makeTexture(gl)
    const fboTex = makeTexture(gl)
    const fbo = gl.createFramebuffer()
    if (!progEasu || !progRcas || !srcTex || !fboTex || !fbo) return null
    return new FsrRenderer(canvas, gl, progEasu, progRcas, srcTex, fboTex, fbo)
  }

  get lost(): boolean {
    return this.gl.isContextLost()
  }

  /**
   * Run `pass` over `frame` and return the scratch canvas (sized tw×th) to
   * drawImage from — or null if the GL context is lost.
   */
  render(
    frame: VideoFrame,
    decodedW: number,
    decodedH: number,
    tw: number,
    th: number,
    pass: Exclude<RenderPass, 'blit'>,
    sharpness: number,
  ): OffscreenCanvas | null {
    const gl = this.gl
    if (gl.isContextLost()) return null
    if (this.canvas.width !== tw) this.canvas.width = tw
    if (this.canvas.height !== th) this.canvas.height = th

    // Upload the frame (Chrome keeps the YUV→RGB conversion on-GPU).
    gl.activeTexture(gl.TEXTURE0)
    gl.bindTexture(gl.TEXTURE_2D, this.srcTex)
    try {
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE, frame)
    } catch {
      // A detached/closed frame or an upload path failure — this frame
      // falls back to the 2D path; the worker decides about permanence.
      return null
    }
    const srcChanged = this.srcW !== decodedW || this.srcH !== decodedH
    this.srcW = decodedW
    this.srcH = decodedH

    if (pass === 'easu-rcas') {
      // Pass 1 — EASU into the FBO texture at target size.
      const fboChanged = this.fboW !== tw || this.fboH !== th
      if (fboChanged) {
        gl.bindTexture(gl.TEXTURE_2D, this.fboTex)
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, tw, th, 0, gl.RGBA, gl.UNSIGNED_BYTE, null)
        this.fboW = tw
        this.fboH = th
      }
      if (srcChanged || fboChanged) this.easuConsDirty = true
      gl.bindFramebuffer(gl.FRAMEBUFFER, this.fbo)
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.fboTex, 0)
      gl.viewport(0, 0, tw, th)
      gl.useProgram(this.progEasu)
      gl.bindTexture(gl.TEXTURE_2D, this.srcTex)
      gl.uniform1i(this.uEasu.src, 0)
      if (this.easuConsDirty) {
        const c = easuConstants(decodedW, decodedH, tw, th)
        gl.uniform4f(this.uEasu.con0, c[0], c[1], c[2], c[3])
        gl.uniform4f(this.uEasu.con1, c[4], c[5], c[6], c[7])
        gl.uniform4f(this.uEasu.con2, c[8], c[9], c[10], c[11])
        gl.uniform4f(this.uEasu.con3, c[12], c[13], c[14], c[15])
        this.easuConsDirty = false
      }
      gl.drawArrays(gl.TRIANGLES, 0, 3)
      // Pass 2 — RCAS from the FBO to the backbuffer (present flip inside).
      gl.bindFramebuffer(gl.FRAMEBUFFER, null)
      gl.viewport(0, 0, tw, th)
      gl.useProgram(this.progRcas)
      gl.bindTexture(gl.TEXTURE_2D, this.fboTex)
      gl.uniform1i(this.uRcas.src, 0)
      gl.uniform2i(this.uRcas.size, tw, th)
      gl.uniform1f(this.uRcas.rcasCon, Math.pow(2, -sharpness))
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    } else {
      // RCAS-only at decoded size, straight to the backbuffer.
      gl.bindFramebuffer(gl.FRAMEBUFFER, null)
      gl.viewport(0, 0, tw, th)
      gl.useProgram(this.progRcas)
      gl.bindTexture(gl.TEXTURE_2D, this.srcTex)
      gl.uniform1i(this.uRcas.src, 0)
      gl.uniform2i(this.uRcas.size, tw, th)
      gl.uniform1f(this.uRcas.rcasCon, Math.pow(2, -sharpness))
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    }
    if (gl.isContextLost()) return null
    return this.canvas
  }

  dispose(): void {
    const gl = this.gl
    gl.deleteTexture(this.srcTex)
    gl.deleteTexture(this.fboTex)
    gl.deleteFramebuffer(this.fbo)
    gl.deleteProgram(this.progEasu)
    gl.deleteProgram(this.progRcas)
  }
}
