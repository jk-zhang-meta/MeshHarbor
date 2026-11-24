// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Variant A: Custom WebGL2 CustomLayerInterface for elevated 3D SLERP arcs on MapLibre globe (S5 R11).
// - Active for zoom < 5, smoothly flattening to surface by z5:
//   h = min(0.3, 0.25 * omega) * clamp((5 - zoom) / 2, 0, 1)
// - Screen-constant CSS pixel width ribbon (triangle strip offset in clip/screen space).
// - Analytic ray-sphere globe horizon occlusion in fragment shader (far-side fragments discarded).
// - CPU 32-sample projection picking for hover & click parity with Variant L.

import type { CustomLayerInterface, CustomRenderMethodInput, Map as MapLibreMap } from 'maplibre-gl'
import {
  aggregatedLinkWidth,
  type AggregatedLink,
  type LinkCarrierClass,
} from './links'
import { getGlobeTokens, hexToRgbaArray, type GlobeThemeMode, type GlobeTokens } from './tokens'

const DEG2RAD = Math.PI / 180
const ARC_SEGMENTS = 32

/** MapLibre globe unit-sphere vector for `(lon, lat)` in degrees (matches `projectToSphere`). */
export function lonLatToGlobeUnitVec(lonDeg: number, latDeg: number): [number, number, number] {
  const lon = lonDeg * DEG2RAD
  const lat = latDeg * DEG2RAD
  const cl = Math.cos(lat)
  return [Math.sin(lon) * cl, Math.sin(lat), Math.cos(lon) * cl]
}

export function slerpUnitVec(
  a: readonly [number, number, number],
  b: readonly [number, number, number],
  t: number,
  omega: number,
): [number, number, number] {
  if (omega < 1e-5) return [a[0], a[1], a[2]]
  if (omega > Math.PI - 1e-3) {
    const ref: [number, number, number] = Math.abs(a[1]) < 0.9 ? [0, 1, 0] : [1, 0, 0]
    const cx = a[1] * ref[2] - a[2] * ref[1]
    const cy = a[2] * ref[0] - a[0] * ref[2]
    const cz = a[0] * ref[1] - a[1] * ref[0]
    const m = Math.hypot(cx, cy, cz) || 1
    const ang = t * Math.PI
    const ca = Math.cos(ang)
    const sa = Math.sin(ang)
    return [a[0] * ca + (cx / m) * sa, a[1] * ca + (cy / m) * sa, a[2] * ca + (cz / m) * sa]
  }
  const sinO = Math.sin(omega)
  const w0 = Math.sin((1 - t) * omega) / sinO
  const w1 = Math.sin(t * omega) / sinO
  const x = w0 * a[0] + w1 * b[0]
  const y = w0 * a[1] + w1 * b[1]
  const z = w0 * a[2] + w1 * b[2]
  const len = Math.hypot(x, y, z) || 1
  return [x / len, y / len, z / len]
}

/** S5 R11 height scale factor in [0, 1] — 1 for zoom <= 3, smoothly flattening to 0 at zoom >= 5. */
export function elevatedArcHeightScale(zoom: number): number {
  return Math.max(0, Math.min(1, (5 - zoom) / 2))
}

/** S5 R11 peak altitude in unit sphere radii: min(0.3, 0.25 * omega) * heightScale. */
export function elevatedArcPeakHeight(omegaRad: number, zoom: number): number {
  return Math.min(0.3, 0.25 * omegaRad) * elevatedArcHeightScale(zoom)
}

/** Invert a column-major 4x4 matrix; returns null if singular. */
function invertMat4(m: ArrayLike<number>): Float64Array | null {
  const inv = new Float64Array(16)
  const m00 = m[0]!, m01 = m[1]!, m02 = m[2]!, m03 = m[3]!
  const m10 = m[4]!, m11 = m[5]!, m12 = m[6]!, m13 = m[7]!
  const m20 = m[8]!, m21 = m[9]!, m22 = m[10]!, m23 = m[11]!
  const m30 = m[12]!, m31 = m[13]!, m32 = m[14]!, m33 = m[15]!

  inv[0] = m11 * m22 * m33 - m11 * m23 * m32 - m21 * m12 * m33 + m21 * m13 * m32 + m31 * m12 * m23 - m31 * m13 * m22
  inv[4] = -m10 * m22 * m33 + m10 * m23 * m32 + m20 * m12 * m33 - m20 * m13 * m32 - m30 * m12 * m23 + m30 * m13 * m22
  inv[8] = m10 * m21 * m33 - m10 * m23 * m31 - m20 * m11 * m33 + m20 * m13 * m31 + m30 * m11 * m23 - m30 * m13 * m21
  inv[12] = -m10 * m21 * m32 + m10 * m22 * m31 + m20 * m11 * m32 - m20 * m12 * m31 - m30 * m11 * m22 + m30 * m12 * m21

  inv[1] = -m01 * m22 * m33 + m01 * m23 * m32 + m21 * m02 * m33 - m21 * m03 * m32 - m31 * m02 * m23 + m31 * m03 * m22
  inv[5] = m00 * m22 * m33 - m00 * m23 * m32 - m20 * m02 * m33 + m20 * m03 * m32 + m30 * m02 * m23 - m30 * m03 * m22
  inv[9] = -m00 * m21 * m33 + m00 * m23 * m31 + m20 * m01 * m33 - m20 * m03 * m31 - m30 * m01 * m23 + m30 * m03 * m21
  inv[13] = m00 * m21 * m32 - m00 * m22 * m31 - m20 * m01 * m32 + m20 * m02 * m31 + m30 * m01 * m22 - m30 * m02 * m21

  inv[2] = m01 * m12 * m33 - m01 * m13 * m32 - m11 * m02 * m33 + m11 * m03 * m32 + m31 * m02 * m13 - m31 * m03 * m12
  inv[6] = -m00 * m12 * m33 + m00 * m13 * m32 + m10 * m02 * m33 - m10 * m03 * m32 - m30 * m02 * m13 + m30 * m03 * m12
  inv[10] = m00 * m11 * m33 - m00 * m13 * m31 - m10 * m01 * m33 + m10 * m03 * m31 + m30 * m01 * m13 - m30 * m03 * m11
  inv[14] = -m00 * m11 * m32 + m00 * m12 * m31 + m10 * m01 * m32 - m10 * m02 * m31 - m30 * m01 * m12 + m30 * m02 * m11

  inv[3] = -m01 * m12 * m23 + m01 * m13 * m22 + m11 * m02 * m23 - m11 * m03 * m22 - m21 * m02 * m13 + m21 * m03 * m12
  inv[7] = m00 * m12 * m23 - m00 * m13 * m22 - m10 * m02 * m23 + m10 * m03 * m22 + m20 * m02 * m13 - m20 * m03 * m12
  inv[11] = -m00 * m11 * m23 + m00 * m13 * m21 + m10 * m01 * m23 - m10 * m03 * m21 - m20 * m01 * m13 + m20 * m03 * m11
  inv[15] = m00 * m11 * m22 - m00 * m12 * m21 - m10 * m01 * m22 + m10 * m02 * m21 + m20 * m01 * m12 - m20 * m02 * m11

  const det = m00 * inv[0]! + m01 * inv[4]! + m02 * inv[8]! + m03 * inv[12]!
  if (!Number.isFinite(det) || Math.abs(det) < 1e-12) return null
  const invDet = 1 / det
  for (let i = 0; i < 16; i++) inv[i] = inv[i]! * invDet
  return inv
}

function mulMat4Vec4(m: ArrayLike<number>, x: number, y: number, z: number, w: number): [number, number, number, number] {
  return [
    m[0]! * x + m[4]! * y + m[8]! * z + m[12]! * w,
    m[1]! * x + m[5]! * y + m[9]! * z + m[13]! * w,
    m[2]! * x + m[6]! * y + m[10]! * z + m[14]! * w,
    m[3]! * x + m[7]! * y + m[11]! * z + m[15]! * w,
  ]
}

/** Recover exact camera eye position in unit-sphere coordinates from inverse globe projection matrix. */
function cameraEyeFromMatrix(mainMatrix: ArrayLike<number>): [number, number, number] | null {
  const inv = invertMat4(mainMatrix)
  if (!inv) return null
  const p0 = mulMat4Vec4(inv, 0, 0, -1, 1)
  const p1 = mulMat4Vec4(inv, 0, 0, 1, 1)
  if (Math.abs(p0[3]) < 1e-9 || Math.abs(p1[3]) < 1e-9) return null
  const near: [number, number, number] = [p0[0] / p0[3], p0[1] / p0[3], p0[2] / p0[3]]
  // In a perspective projection, unprojecting two different rays (NDC (0,0) and (0.5,0))
  // intersects at the exact camera eye!
  const q0 = mulMat4Vec4(inv, 0.5, 0, -1, 1)
  const q1 = mulMat4Vec4(inv, 0.5, 0, 1, 1)
  if (Math.abs(q0[3]) < 1e-9 || Math.abs(q1[3]) < 1e-9) return near

  const a0 = near
  const a1: [number, number, number] = [p1[0] / p1[3], p1[1] / p1[3], p1[2] / p1[3]]
  const b0: [number, number, number] = [q0[0] / q0[3], q0[1] / q0[3], q0[2] / q0[3]]
  const b1: [number, number, number] = [q1[0] / q1[3], q1[1] / q1[3], q1[2] / q1[3]]

  // Closest point between two rays a0 + s*da and b0 + t*db
  const da: [number, number, number] = [a1[0] - a0[0], a1[1] - a0[1], a1[2] - a0[2]]
  const db: [number, number, number] = [b1[0] - b0[0], b1[1] - b0[1], b1[2] - b0[2]]
  const w0: [number, number, number] = [a0[0] - b0[0], a0[1] - b0[1], a0[2] - b0[2]]
  const a = da[0] * da[0] + da[1] * da[1] + da[2] * da[2]
  const b = da[0] * db[0] + da[1] * db[1] + da[2] * db[2]
  const c = db[0] * db[0] + db[1] * db[1] + db[2] * db[2]
  const d = da[0] * w0[0] + da[1] * w0[1] + da[2] * w0[2]
  const e = db[0] * w0[0] + db[1] * w0[1] + db[2] * w0[2]
  const denom = a * c - b * b
  if (Math.abs(denom) < 1e-10) return near
  const s = (b * e - c * d) / denom
  return [a0[0] + s * da[0], a0[1] + s * da[1], a0[2] + s * da[2]]
}

/** Analytic ray-sphere occlusion check matching the fragment shader. */
function isOccludedBySphere(
  eye: readonly [number, number, number],
  p: readonly [number, number, number],
): boolean {
  const dx = p[0] - eye[0]
  const dy = p[1] - eye[1]
  const dz = p[2] - eye[2]
  const a = dx * dx + dy * dy + dz * dz
  const b = 2 * (eye[0] * dx + eye[1] * dy + eye[2] * dz)
  const c = eye[0] * eye[0] + eye[1] * eye[1] + eye[2] * eye[2] - 0.9985 * 0.9985
  const disc = b * b - 4 * a * c
  if (disc <= 0 || a < 1e-12) return false
  const tHit = (-b - Math.sqrt(disc)) / (2 * a)
  return tHit > 0 && tHit < 0.996
}

function colorForCarrier(cls: LinkCarrierClass, stalled: boolean, tokens: GlobeTokens): string {
  if (stalled) return tokens.stalled
  switch (cls) {
    case 'direct':
      return tokens.direct
    case 'tunnel':
      return tokens.tunnel
    case 'relay':
      return tokens.relay
    case 'derp':
      return tokens.derp
    case 'blocked':
      return tokens.blocked
  }
}

/** Dash style code passed to fragment shader matching S5 R7 ratios: 0=solid, 1=relay[4,3], 2=derp[2,2], 3=dotted[1,2.2]. */
function dashModeForLink(cls: LinkCarrierClass, stalled: boolean): number {
  if (stalled) return 3
  if (cls === 'blocked') return 3
  if (cls === 'relay') return 1
  if (cls === 'derp') return 2
  return 0
}

const VERTEX_SHADER = `#version 300 es
precision highp float;

layout(location = 0) in vec3 a_pos;
layout(location = 1) in vec3 a_next;
layout(location = 2) in float a_side;
layout(location = 3) in float a_widthPx;
layout(location = 4) in float a_arcT;
layout(location = 5) in float a_arcPeak;
layout(location = 6) in float a_dashMode;
layout(location = 7) in vec4 a_color;

uniform mat4 u_matrix;
uniform vec2 u_viewport;
uniform float u_heightScale;

out vec3 v_worldPos;
out vec4 v_color;
out float v_arcDistPx;
out float v_dashMode;
out float v_widthPx;
out float v_edgeDist;

void main() {
  float elev = sin(a_arcT * 3.14159265359) * a_arcPeak * u_heightScale;
  float nextT = min(1.0, a_arcT + ${1 / ARC_SEGMENTS});
  float nextElev = sin(nextT * 3.14159265359) * a_arcPeak * u_heightScale;

  vec3 worldPos = a_pos * (1.0 + elev);
  vec3 nextWorld = a_next * (1.0 + nextElev);

  vec4 clipCur = u_matrix * vec4(worldPos, 1.0);
  vec4 clipNext = u_matrix * vec4(nextWorld, 1.0);

  vec2 ndcCur = clipCur.xy / max(abs(clipCur.w), 0.0001);
  vec2 ndcNext = clipNext.xy / max(abs(clipNext.w), 0.0001);

  vec2 scrDir = (ndcNext - ndcCur) * u_viewport * 0.5;
  float len = length(scrDir);
  vec2 dir = len > 0.0001 ? scrDir / len : vec2(1.0, 0.0);
  vec2 perp = vec2(-dir.y, dir.x);

  // Add 0.75px AA pad on each side for smooth sub-pixel alpha edges
  float halfWidth = a_widthPx * 0.5 + 0.75;
  vec2 offsetNdc = (perp * a_side * halfWidth) / (u_viewport * 0.5);

  vec4 outClip = clipCur;
  outClip.xy += offsetNdc * clipCur.w;
  // Keep depth inside [-w, w] so GL clip doesn't drop elevated arcs; sphere occlusion runs in FS.
  outClip.z = 0.0;

  gl_Position = outClip;
  v_worldPos = worldPos;
  v_color = a_color;
  v_arcDistPx = a_arcT * 180.0;
  v_dashMode = a_dashMode;
  v_widthPx = a_widthPx;
  v_edgeDist = a_side * halfWidth;
}
`

const FRAGMENT_SHADER = `#version 300 es
precision highp float;

uniform vec3 u_cameraEye;

in vec3 v_worldPos;
in vec4 v_color;
in float v_arcDistPx;
in float v_dashMode;
in float v_widthPx;
in float v_edgeDist;

out vec4 fragColor;

void main() {
  // Analytic ray-sphere horizon occlusion against the opaque unit Earth sphere
  vec3 ray = v_worldPos - u_cameraEye;
  float a = dot(ray, ray);
  float b = 2.0 * dot(u_cameraEye, ray);
  float c = dot(u_cameraEye, u_cameraEye) - 0.9985 * 0.9985;
  float disc = b * b - 4.0 * a * c;
  if (disc > 0.0 && a > 1e-8) {
    float tHit = (-b - sqrt(disc)) / (2.0 * a);
    if (tHit > 0.0 && tHit < 0.996) {
      discard;
    }
  }

  // Soft edge anti-aliasing for crisp screen-constant CSS pixel ribbon
  float halfCore = v_widthPx * 0.5;
  float aa = 1.0 - smoothstep(max(0.0, halfCore - 0.35), halfCore + 0.65, abs(v_edgeDist));
  if (aa <= 0.01) discard;

  // Dash patterns matching S5 R7 ratios
  float dashAlpha = 1.0;
  if (v_dashMode > 0.5 && v_dashMode < 1.5) {
    // relay: [4, 3]
    float m = mod(v_arcDistPx, 7.0);
    dashAlpha = m <= 4.0 ? 1.0 : 0.0;
  } else if (v_dashMode >= 1.5 && v_dashMode < 2.5) {
    // derp: [2, 2]
    float m = mod(v_arcDistPx, 4.0);
    dashAlpha = m <= 2.0 ? 1.0 : 0.0;
  } else if (v_dashMode >= 2.5) {
    // stalled / blocked: dotted [1.1, 2.2]
    float m = mod(v_arcDistPx, 3.3);
    dashAlpha = m <= 1.1 ? 1.0 : 0.0;
  }
  if (dashAlpha <= 0.01) discard;

  float alpha = v_color.a * aa * dashAlpha;
  fragColor = vec4(v_color.rgb * alpha, alpha);
}
`

// Stride: pos(3) + next(3) + side(1) + width(1) + arcT(1) + arcPeak(1) + dashMode(1) + color(4) = 15 floats
const FLOATS_PER_VERTEX = 15

export interface ElevatedArcDrawEntry {
  link: AggregatedLink
  isEgo: boolean
  highlighted: boolean
  dimmed: boolean
}

export class ElevatedArcsLayer implements CustomLayerInterface {
  readonly id = 'mh-links-elevated'
  readonly type = 'custom' as const
  readonly renderingMode = '2d' as const

  private map: MapLibreMap | null = null
  private gl: WebGL2RenderingContext | null = null
  private program: WebGLProgram | null = null
  private vao: WebGLVertexArrayObject | null = null
  private vbo: WebGLBuffer | null = null
  private vertexCount = 0
  private enabled = false
  private theme: GlobeThemeMode = 'dark'
  private entries: ElevatedArcDrawEntry[] = []
  private dirty = true

  private uMatrix: WebGLUniformLocation | null = null
  private uViewport: WebGLUniformLocation | null = null
  private uHeightScale: WebGLUniformLocation | null = null
  private uCameraEye: WebGLUniformLocation | null = null

  private lastMainMatrix: Float64Array | null = null
  private lastCameraEye: [number, number, number] | null = null

  setEnabled(enabled: boolean): void {
    if (this.enabled === enabled) return
    this.enabled = enabled
    this.map?.triggerRepaint()
  }

  setTheme(theme: GlobeThemeMode): void {
    if (this.theme === theme) return
    this.theme = theme
    this.dirty = true
    if (this.enabled) this.map?.triggerRepaint()
  }

  setLinks(entries: ElevatedArcDrawEntry[]): void {
    this.entries = entries
    this.dirty = true
    if (this.enabled) this.map?.triggerRepaint()
  }

  onAdd(map: MapLibreMap, gl: WebGL2RenderingContext): void {
    this.map = map
    this.gl = gl
    this.initGl(gl)
  }

  onRemove(_map: MapLibreMap, gl: WebGL2RenderingContext): void {
    if (this.vbo) gl.deleteBuffer(this.vbo)
    if (this.vao) gl.deleteVertexArray(this.vao)
    if (this.program) gl.deleteProgram(this.program)
    this.vbo = null
    this.vao = null
    this.program = null
    this.gl = null
    this.map = null
  }

  private initGl(gl: WebGL2RenderingContext): void {
    const compile = (type: number, src: string): WebGLShader => {
      const sh = gl.createShader(type)!
      gl.shaderSource(sh, src)
      gl.compileShader(sh)
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        const log = gl.getShaderInfoLog(sh)
        gl.deleteShader(sh)
        throw new Error(`ElevatedArcsLayer shader error: ${log}`)
      }
      return sh
    }

    const vs = compile(gl.VERTEX_SHADER, VERTEX_SHADER)
    const fs = compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER)
    const prog = gl.createProgram()!
    gl.attachShader(prog, vs)
    gl.attachShader(prog, fs)
    gl.linkProgram(prog)
    gl.deleteShader(vs)
    gl.deleteShader(fs)
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      throw new Error(`ElevatedArcsLayer link error: ${gl.getProgramInfoLog(prog)}`)
    }

    this.program = prog
    this.uMatrix = gl.getUniformLocation(prog, 'u_matrix')
    this.uViewport = gl.getUniformLocation(prog, 'u_viewport')
    this.uHeightScale = gl.getUniformLocation(prog, 'u_heightScale')
    this.uCameraEye = gl.getUniformLocation(prog, 'u_cameraEye')

    this.vao = gl.createVertexArray()
    this.vbo = gl.createBuffer()
    gl.bindVertexArray(this.vao)
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vbo)

    const stride = FLOATS_PER_VERTEX * 4
    gl.enableVertexAttribArray(0)
    gl.vertexAttribPointer(0, 3, gl.FLOAT, false, stride, 0)
    gl.enableVertexAttribArray(1)
    gl.vertexAttribPointer(1, 3, gl.FLOAT, false, stride, 3 * 4)
    gl.enableVertexAttribArray(2)
    gl.vertexAttribPointer(2, 1, gl.FLOAT, false, stride, 6 * 4)
    gl.enableVertexAttribArray(3)
    gl.vertexAttribPointer(3, 1, gl.FLOAT, false, stride, 7 * 4)
    gl.enableVertexAttribArray(4)
    gl.vertexAttribPointer(4, 1, gl.FLOAT, false, stride, 8 * 4)
    gl.enableVertexAttribArray(5)
    gl.vertexAttribPointer(5, 1, gl.FLOAT, false, stride, 9 * 4)
    gl.enableVertexAttribArray(6)
    gl.vertexAttribPointer(6, 1, gl.FLOAT, false, stride, 10 * 4)
    gl.enableVertexAttribArray(7)
    gl.vertexAttribPointer(7, 4, gl.FLOAT, false, stride, 11 * 4)

    gl.bindVertexArray(null)
    this.dirty = true
  }

  private rebuildBuffer(): void {
    const gl = this.gl
    if (!gl || !this.vbo) return
    this.dirty = false

    const tokens = getGlobeTokens(this.theme)
    const vertsPerArc = ARC_SEGMENTS * 6
    const data = new Float32Array(this.entries.length * vertsPerArc * FLOATS_PER_VERTEX)
    let cursor = 0

    const pushVert = (
      p: readonly [number, number, number],
      next: readonly [number, number, number],
      side: number,
      widthPx: number,
      arcT: number,
      peak: number,
      dashMode: number,
      rgba: readonly [number, number, number, number],
    ) => {
      data[cursor++] = p[0]
      data[cursor++] = p[1]
      data[cursor++] = p[2]
      data[cursor++] = next[0]
      data[cursor++] = next[1]
      data[cursor++] = next[2]
      data[cursor++] = side
      data[cursor++] = widthPx
      data[cursor++] = arcT
      data[cursor++] = peak
      data[cursor++] = dashMode
      data[cursor++] = rgba[0]
      data[cursor++] = rgba[1]
      data[cursor++] = rgba[2]
      data[cursor++] = rgba[3]
    }

    for (const entry of this.entries) {
      const { link, isEgo, highlighted, dimmed } = entry
      const a = lonLatToGlobeUnitVec(link.fromLonLat[0], link.fromLonLat[1])
      const b = lonLatToGlobeUnitVec(link.toLonLat[0], link.toLonLat[1])
      const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
      const omega = Math.acos(dot)
      const peak = Math.min(0.3, 0.25 * omega)

      const baseWidth = isEgo ? 1.5 : aggregatedLinkWidth(link.count)
      const widthPx = highlighted ? baseWidth + 1 : baseWidth
      const opacity = highlighted
        ? 1.0
        : isEgo
          ? 1.0
          : dimmed
            ? 0.15
            : link.healthy
              ? 0.45
              : 0.9

      const firstColor = hexToRgbaArray(
        colorForCarrier(link.asymmetric ? link.fromClass : link.worstClass, link.anyStalled, tokens),
        opacity,
      )
      const secondColor = hexToRgbaArray(
        colorForCarrier(link.asymmetric ? link.toClass : link.worstClass, link.anyStalled, tokens),
        opacity,
      )
      const firstDash = dashModeForLink(
        link.asymmetric ? link.fromClass : link.worstClass,
        link.anyStalled,
      )
      const secondDash = dashModeForLink(
        link.asymmetric ? link.toClass : link.worstClass,
        link.anyStalled,
      )

      const pts: Array<[number, number, number]> = []
      for (let i = 0; i <= ARC_SEGMENTS; i++) {
        pts.push(slerpUnitVec(a, b, i / ARC_SEGMENTS, omega))
      }

      for (let i = 0; i < ARC_SEGMENTS; i++) {
        const t0 = i / ARC_SEGMENTS
        const t1 = (i + 1) / ARC_SEGMENTS
        const p0 = pts[i]!
        const p1 = pts[i + 1]!
        const p2 = pts[Math.min(ARC_SEGMENTS, i + 2)]!
        const rgba = t0 < 0.5 ? firstColor : secondColor
        const dash = t0 < 0.5 ? firstDash : secondDash

        // Quad as two triangles
        pushVert(p0, p1, -1, widthPx, t0, peak, dash, rgba)
        pushVert(p0, p1, 1, widthPx, t0, peak, dash, rgba)
        pushVert(p1, p2, 1, widthPx, t1, peak, dash, rgba)

        pushVert(p0, p1, -1, widthPx, t0, peak, dash, rgba)
        pushVert(p1, p2, 1, widthPx, t1, peak, dash, rgba)
        pushVert(p1, p2, -1, widthPx, t1, peak, dash, rgba)
      }
    }

    this.vertexCount = cursor / FLOATS_PER_VERTEX
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vbo)
    gl.bufferData(gl.ARRAY_BUFFER, data.subarray(0, cursor), gl.DYNAMIC_DRAW)
  }

  render(gl: WebGL2RenderingContext, args: CustomRenderMethodInput): void {
    if (!this.enabled || !this.map || !this.program || !this.vao) return
    const zoom = this.map.getZoom()
    const heightScale = elevatedArcHeightScale(zoom)
    if (heightScale <= 0.001) return

    if (this.dirty) this.rebuildBuffer()
    if (this.vertexCount === 0) return

    const mainMatrix = args.defaultProjectionData.mainMatrix
    this.lastMainMatrix = new Float64Array(mainMatrix)
    const eye = cameraEyeFromMatrix(mainMatrix)
    if (!eye) return
    this.lastCameraEye = eye

    const canvas = this.map.getCanvas()
    const dpr = this.map.getPixelRatio()
    const cssW = canvas.width / Math.max(dpr, 0.5)
    const cssH = canvas.height / Math.max(dpr, 0.5)

    gl.useProgram(this.program)
    gl.bindVertexArray(this.vao)
    gl.enable(gl.BLEND)
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA)
    gl.disable(gl.DEPTH_TEST)
    gl.disable(gl.CULL_FACE)

    gl.uniformMatrix4fv(this.uMatrix, false, new Float32Array(mainMatrix))
    gl.uniform2f(this.uViewport, cssW, cssH)
    gl.uniform1f(this.uHeightScale, heightScale)
    gl.uniform3f(this.uCameraEye, eye[0], eye[1], eye[2])

    gl.drawArrays(gl.TRIANGLES, 0, this.vertexCount)
    gl.bindVertexArray(null)
  }

  /**
   * CPU 32-sample projection picking for elevated arcs (S5 R11).
   * Returns the nearest visible elevated arc key within `tolerancePx` of `(px, py)`.
   */
  pickAtPoint(px: number, py: number, tolerancePx: number): AggregatedLink | null {
    if (!this.enabled || !this.map || !this.lastMainMatrix || !this.lastCameraEye) return null
    const zoom = this.map.getZoom()
    const heightScale = elevatedArcHeightScale(zoom)
    if (heightScale <= 0.001) return null

    const canvas = this.map.getCanvas()
    const dpr = this.map.getPixelRatio()
    const cssW = canvas.width / Math.max(dpr, 0.5)
    const cssH = canvas.height / Math.max(dpr, 0.5)
    const m = this.lastMainMatrix
    const eye = this.lastCameraEye

    let best: AggregatedLink | null = null
    let bestDistSq = tolerancePx * tolerancePx

    for (const { link } of this.entries) {
      const a = lonLatToGlobeUnitVec(link.fromLonLat[0], link.fromLonLat[1])
      const b = lonLatToGlobeUnitVec(link.toLonLat[0], link.toLonLat[1])
      const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
      const omega = Math.acos(dot)
      const peak = Math.min(0.3, 0.25 * omega) * heightScale

      let prevX: number | null = null
      let prevY: number | null = null

      for (let i = 0; i <= ARC_SEGMENTS; i++) {
        const t = i / ARC_SEGMENTS
        const u = slerpUnitVec(a, b, t, omega)
        const r = 1 + Math.sin(t * Math.PI) * peak
        const p: [number, number, number] = [u[0] * r, u[1] * r, u[2] * r]
        if (isOccludedBySphere(eye, p)) {
          prevX = null
          prevY = null
          continue
        }
        const clip = mulMat4Vec4(m, p[0], p[1], p[2], 1)
        if (clip[3] <= 0.0001) {
          prevX = null
          prevY = null
          continue
        }
        const sx = ((clip[0] / clip[3]) * 0.5 + 0.5) * cssW
        const sy = (0.5 - (clip[1] / clip[3]) * 0.5) * cssH

        if (prevX != null && prevY != null) {
          const dx = sx - prevX
          const dy = sy - prevY
          const lenSq = dx * dx + dy * dy
          const proj =
            lenSq > 1e-6 ? Math.max(0, Math.min(1, ((px - prevX) * dx + (py - prevY) * dy) / lenSq)) : 0
          const cx = prevX + proj * dx
          const cy = prevY + proj * dy
          const dSq = (px - cx) ** 2 + (py - cy) ** 2
          if (dSq < bestDistSq) {
            bestDistSq = dSq
            best = link
          }
        }
        prevX = sx
        prevY = sy
      }
    }

    return best
  }
}
