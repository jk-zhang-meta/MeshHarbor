// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Builds the self-hosted Natural Earth 1:50m (`world-atlas/countries-50m.json`)
// Earth surface texture AND crisp 3D vector coastline/border LineSegments for
// Three.js. Zero external CDNs, zero raster tiles to host.
import { BufferAttribute, BufferGeometry, CanvasTexture, SRGBColorSpace } from 'three'
import { geoEquirectangular, geoGraticule10, geoPath, type GeoPermissibleObjects } from 'd3-geo'
import { feature, mesh as topoMesh } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import { latLonToVec3 } from './geoLayout'

export interface GlobeThemePalette {
  isDark: boolean
  backdrop: string
  oceanTop: string
  oceanMid: string
  oceanPole: string
  landFill: string
  landStroke: string
  graticule: string
  vectorBorder: string
  vectorCoast: string
  atmosphereOuter: string
  atmosphereInner: string
  atmosphereIntensity: number
  specular: string
  ambientHex: number
  ambientIntensity: number
  sunIntensity: number
  nodeOnline: string
  nodeStale: string
  nodeOffline: string
  centreColor: string
  centreRing: string
  controlSpoke: string
  labelBg: string
  labelText: string
  labelBorder: string
}

/**
 * Two distinctive MeshHarbor palettes derived directly from `plugins/vuetify.ts`
 * and `styles/theme.css`:
 *  - Dark ("Harbor Night Chart"): deep harbor slate + luminous teal coastlines & halo.
 *  - Light ("Harbor Nautical Paper"): porcelain ocean + architectural paper land +
 *    crisp ink borders + delicate coastal-teal Fresnel limb.
 */
export function getGlobePalette(isDark: boolean): GlobeThemePalette {
  if (isDark) {
    return {
      isDark: true,
      backdrop: '#0B1319',
      oceanTop: '#0F202B',
      oceanMid: '#0B1821',
      oceanPole: '#081219',
      landFill: '#172C38',
      landStroke: 'rgba(60, 199, 185, 0.28)',
      graticule: 'rgba(60, 199, 185, 0.065)',
      vectorBorder: '#2C6F73',
      vectorCoast: '#3CC7B9',
      atmosphereOuter: '#3CC7B9',
      atmosphereInner: '#5CE0D3',
      atmosphereIntensity: 0.78,
      specular: '#1A3A47',
      ambientHex: 0xdaf2f0,
      ambientIntensity: 1.55,
      sunIntensity: 0.9,
      nodeOnline: '#3CCB7F',
      nodeStale: '#E0A93B',
      nodeOffline: '#6D818E',
      centreColor: '#3CC7B9',
      centreRing: '#F0965A',
      controlSpoke: '#3CC7B9',
      labelBg: 'rgba(14, 21, 26, 0.86)',
      labelText: '#E6EEF2',
      labelBorder: 'rgba(60, 199, 185, 0.34)',
    }
  }
  return {
    isDark: false,
    backdrop: '#EEF3F6',
    oceanTop: '#DCE9EF',
    oceanMid: '#D0E1E9',
    oceanPole: '#C5D9E3',
    landFill: '#F7FAFB',
    landStroke: 'rgba(16, 33, 43, 0.16)',
    graticule: 'rgba(10, 143, 134, 0.085)',
    vectorBorder: '#8BA4B0',
    vectorCoast: '#0A8F86',
    atmosphereOuter: '#0A8F86',
    atmosphereInner: '#2BA89E',
    atmosphereIntensity: 0.42,
    specular: '#FFFFFF',
    ambientHex: 0xffffff,
    ambientIntensity: 2.05,
    sunIntensity: 0.58,
    nodeOnline: '#1F9D57',
    nodeStale: '#B97E08',
    nodeOffline: '#8899A4',
    centreColor: '#0A8F86',
    centreRing: '#E07A2E',
    controlSpoke: '#0A8F86',
    labelBg: 'rgba(255, 255, 255, 0.92)',
    labelText: '#10212B',
    labelBorder: 'rgba(16, 33, 43, 0.18)',
  }
}

type WorldTopology = Topology<{
  countries: GeometryCollection
  land: GeometryCollection
}>

let cachedTopoPromise: Promise<WorldTopology> | null = null

export function loadWorldTopology(): Promise<WorldTopology> {
  if (!cachedTopoPromise) {
    cachedTopoPromise = import('world-atlas/countries-50m.json').then(
      (mod) => (mod.default ?? mod) as unknown as WorldTopology,
    )
  }
  return cachedTopoPromise
}

/**
 * Paint a crisp equirectangular Earth texture from Natural Earth 1:50m TopoJSON.
 * Uses 2048×1024 on mobile / narrow viewports and 3072×1536 on high-DPI desktop
 * for fast startup (<50 ms) while vector LineSegments supply infinite coastline zoom.
 */
export function createEarthCanvasTexture(
  topo: WorldTopology,
  palette: GlobeThemePalette,
  highRes = true,
): CanvasTexture {
  const W = highRes ? 3072 : 2048
  const H = W / 2
  const canvas = document.createElement('canvas')
  canvas.width = W
  canvas.height = H
  const ctx = canvas.getContext('2d')!

  // Ocean bathymetric vertical gradient (equator slightly warmer, poles deeper)
  const oceanGrad = ctx.createLinearGradient(0, 0, 0, H)
  oceanGrad.addColorStop(0, palette.oceanPole)
  oceanGrad.addColorStop(0.22, palette.oceanMid)
  oceanGrad.addColorStop(0.5, palette.oceanTop)
  oceanGrad.addColorStop(0.78, palette.oceanMid)
  oceanGrad.addColorStop(1, palette.oceanPole)
  ctx.fillStyle = oceanGrad
  ctx.fillRect(0, 0, W, H)

  // Use d3-geo's equirectangular projection with exact antimeridian cutting so
  // Russia, Antarctica, and Fiji never produce horizontal wrap stripes.
  const proj = geoEquirectangular()
    .scale(W / (2 * Math.PI))
    .translate([W / 2, H / 2])
  const draw = geoPath(proj, ctx)

  // Maritime 10° graticule
  ctx.beginPath()
  draw(geoGraticule10())
  ctx.strokeStyle = palette.graticule
  ctx.lineWidth = highRes ? 1.0 : 0.85
  ctx.stroke()

  // Natural Earth 1:50m land polygons
  const landGeo = feature(topo, topo.objects.land) as unknown as GeoPermissibleObjects
  ctx.beginPath()
  draw(landGeo)
  ctx.fillStyle = palette.landFill
  ctx.fill()
  ctx.strokeStyle = palette.landStroke
  ctx.lineWidth = highRes ? 1.1 : 0.85
  ctx.stroke()

  const texture = new CanvasTexture(canvas)
  texture.colorSpace = SRGBColorSpace
  texture.anisotropy = 4
  texture.needsUpdate = true
  return texture
}

/**
 * Build true 3D vector coastline & country-border `BufferGeometry` (`LineSegments`)
 * directly on the unit sphere so zooming into any region stays razor-sharp with
 * zero raster blur.
 */
export function createVectorBorderGeometries(
  topo: WorldTopology,
  radius = 1.0022,
): { coastlines: BufferGeometry; borders: BufferGeometry } {
  const buildFromMultiLine = (multi: GeoJSON.MultiLineString, r: number): BufferGeometry => {
    let segCount = 0
    for (const line of multi.coordinates) {
      if (line.length > 1) segCount += line.length - 1
    }
    const positions = new Float32Array(segCount * 6)
    let ptr = 0
    for (const line of multi.coordinates) {
      for (let i = 0; i < line.length - 1; i++) {
        const p0 = line[i]!
        const p1 = line[i + 1]!
        // Skip antimeridian wrap artifacts
        if (Math.abs(p1[0]! - p0[0]!) > 90) continue
        const v0 = latLonToVec3(p0[1]!, p0[0]!, r)
        const v1 = latLonToVec3(p1[1]!, p1[0]!, r)
        positions[ptr++] = v0.x
        positions[ptr++] = v0.y
        positions[ptr++] = v0.z
        positions[ptr++] = v1.x
        positions[ptr++] = v1.y
        positions[ptr++] = v1.z
      }
    }
    const geo = new BufferGeometry()
    geo.setAttribute('position', new BufferAttribute(positions.subarray(0, ptr), 3))
    return geo
  }

  // Outer coastlines (`a === b`) vs interior country borders (`a !== b`)
  const coastMulti = topoMesh(topo, topo.objects.countries, (a, b) => a === b)
  const borderMulti = topoMesh(topo, topo.objects.countries, (a, b) => a !== b)

  return {
    coastlines: buildFromMultiLine(coastMulti, radius + 0.0005),
    borders: buildFromMultiLine(borderMulti, radius),
  }
}
