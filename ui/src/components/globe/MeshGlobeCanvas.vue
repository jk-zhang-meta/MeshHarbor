<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <div
    ref="stageEl"
    class="mh-globe-stage"
    :class="{ 'mh-globe-stage--dark': isDark, 'mh-globe-stage--mobile': isMobile }"
    :style="{ height: `${stageHeight}px` }"
    tabindex="0"
    role="application"
    :aria-label="ariaLabel || $t('mh.mesh.globeAria')"
    data-testid="mesh-globe-stage"
    @keydown="onKeyDown"
  >
    <canvas
      ref="canvasEl"
      class="mh-globe-canvas"
      data-testid="mesh-globe-canvas"
      @pointerdown="onPointerDown"
      @pointermove="onPointerMove"
      @pointerup="onPointerUp"
      @pointercancel="onPointerUp"
      @pointerleave="onPointerLeave"
      @wheel.prevent="onWheel"
    />

    <!-- Collision-culled projected HTML node labels (crisp typography) -->
    <div class="mh-globe-labels" aria-hidden="true">
      <div
        v-for="lbl in visibleLabels"
        :key="lbl.id"
        class="mh-globe-label"
        :class="{
          'mh-globe-label--centre': lbl.isCentre,
          'mh-globe-label--active': lbl.active,
          'mh-globe-label--gateway': lbl.isGateway,
        }"
        :style="{ transform: `translate(${lbl.x}px, ${lbl.y}px)` }"
      >
        <span class="mh-globe-label__dot" :style="{ background: lbl.color }" />
        <span>{{ lbl.text }}</span>
      </div>
    </div>

    <!-- Compact hover tooltip (desktop pointer hover when not occluded) -->
    <div
      v-if="hoverTip && !isMobile"
      class="mh-globe-tip"
      data-testid="globe-hover-tooltip"
      :style="{ left: `${hoverTip.x}px`, top: `${hoverTip.y}px` }"
    >
      <div class="mh-globe-tip__title">
        <span class="mh-globe-label__dot" :style="{ background: hoverTip.color }" />
        <span>{{ hoverTip.title }}</span>
      </div>
      <div v-if="hoverTip.subtitle" class="mh-globe-tip__sub">{{ hoverTip.subtitle }}</div>
    </div>

    <!-- Compact HUD controls (zoom, reset, auto-rotate toggle) -->
    <div class="mh-globe-hud" role="toolbar" :aria-label="$t('mh.mesh.controls.toolbarAria')">
      <v-btn
        icon="mdi-plus"
        size="x-small"
        variant="text"
        :title="$t('mh.mesh.controls.zoomIn')"
        :aria-label="$t('mh.mesh.controls.zoomIn')"
        @click.stop="zoomBy(-0.42)"
      />
      <v-btn
        icon="mdi-minus"
        size="x-small"
        variant="text"
        :title="$t('mh.mesh.controls.zoomOut')"
        :aria-label="$t('mh.mesh.controls.zoomOut')"
        @click.stop="zoomBy(0.42)"
      />
      <v-btn
        icon="mdi-crosshairs-gps"
        size="x-small"
        variant="text"
        :title="$t('mh.mesh.controls.reset')"
        :aria-label="$t('mh.mesh.controls.reset')"
        @click.stop="resetView"
      />
      <v-btn
        v-if="!reducedMotion"
        :icon="autoRotate ? 'mdi-pause' : 'mdi-play'"
        size="x-small"
        variant="text"
        :title="autoRotate ? $t('mh.mesh.controls.pauseRotate') : $t('mh.mesh.controls.resumeRotate')"
        :aria-label="autoRotate ? $t('mh.mesh.controls.pauseRotate') : $t('mh.mesh.controls.resumeRotate')"
        @click.stop="autoRotate = !autoRotate"
      />
    </div>

    <!-- Self-hosted Natural Earth public-domain attribution -->
    <div class="mh-globe-attrib" data-testid="globe-attribution">
      {{ $t('mh.mesh.attribution') }}
    </div>

    <!-- Pinned rich detail card (desktop floating card / mobile bottom sheet) -->
    <globe-detail-panel
      v-if="showDetailPanel"
      :node="selectedNode"
      :arc="selectedArc"
      :nodes="placedNodes"
      :arcs="effectiveArcs"
      :is-mobile="isMobile"
      :show-open-action="showOpenDeviceAction"
      @close="clearSelection"
      @open-device="emit('open-device', $event)"
      @focus-node="focusNodeById"
      @focus-arc="focusArcByKey"
    />
  </div>
</template>

<script setup lang="ts">
import {
  AmbientLight,
  BackSide,
  BufferAttribute,
  BufferGeometry,
  CanvasTexture,
  Color,
  DirectionalLight,
  FrontSide,
  Group,
  InstancedMesh,
  LineBasicMaterial,
  LineSegments,
  Matrix4,
  Mesh,
  MeshBasicMaterial,
  MeshPhongMaterial,
  NormalBlending,
  OctahedronGeometry,
  PerspectiveCamera,
  Quaternion,
  RingGeometry,
  Scene,
  ShaderMaterial,
  SphereGeometry,
  Vector3,
  WebGLRenderer,
} from 'three'
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useTheme } from 'vuetify'
import { qualifiedCarrier } from '@/utils/mesh'
import GlobeDetailPanel from './GlobeDetailPanel.vue'
import {
  createEarthCanvasTexture,
  createVectorBorderGeometries,
  getGlobePalette,
  loadWorldTopology,
  type GlobeThemePalette,
} from './earthTexture'
import {
  buildGreatCircleArcPoints,
  computeArcVisualStates,
  latLonToVec3,
  placeGlobeNodes,
} from './geoLayout'
import type { GlobeArc, GlobeCenter, GlobeNode, PlacedGlobeCenter, PlacedGlobeNode } from './types'
import { prefersReducedMotion } from './webgl'

const MIN_DIST = 1.35
const MAX_DIST = 4.6
const DEFAULT_DIST_LANDSCAPE = 3.38
const ARC_SEGMENTS = 36

// Marker sizes, in globe radii at the default camera distance.
const NODE_CORE_R = 0.0105
const NODE_RING_IN = 0.013
const NODE_RING_OUT = 0.0195
const NODE_CORE_LIFT = 0.012
const NODE_RING_LIFT = 0.008
const CENTRE_BEACON_R = 0.02
const CENTRE_RING_IN = 0.026
const CENTRE_RING_OUT = 0.034
// How much a marker still grows on screen as the camera zooms in: 0 keeps its screen size,
// 1 grows it with the globe (the old behaviour, where a dot covered a whole region up close).
const MARKER_ZOOM_GROWTH = 0.15

function computeDefaultDist(w: number, h: number): number {
  const aspect = w / Math.max(1, h)
  // On portrait phones (aspect < 1), pull back cleanly so the entire glowing
  // sphere & atmosphere stay framed inside the narrow column without side clipping.
  return aspect < 1 ? Math.min(MAX_DIST, DEFAULT_DIST_LANDSCAPE / Math.max(0.76, aspect)) : DEFAULT_DIST_LANDSCAPE
}

const props = withDefaults(
  defineProps<{
    nodes: readonly GlobeNode[]
    arcs: readonly GlobeArc[]
    center?: GlobeCenter | null
    showControlPlane?: boolean
    showDetailPanel?: boolean
    showOpenDeviceAction?: boolean
    height?: number
    ariaLabel?: string
  }>(),
  {
    center: null,
    showControlPlane: true,
    showDetailPanel: true,
    showOpenDeviceAction: true,
    height: 0,
    ariaLabel: '',
  },
)

const emit = defineEmits<{
  (e: 'node-click', nodeId: string): void
  (e: 'arc-click', arcKey: string): void
  (e: 'open-device', nodeId: string): void
  (e: 'webgl-error', reason: string): void
}>()

const { t } = useI18n()
const theme = useTheme()
const isDark = computed(() => theme.current.value.dark)
const palette = computed<GlobeThemePalette>(() => getGlobePalette(isDark.value))

const stageEl = ref<HTMLElement | null>(null)
const canvasEl = ref<HTMLCanvasElement | null>(null)
const stageWidth = ref(800)
const isMobile = computed(() => stageWidth.value < 600)
const stageHeight = computed(() => {
  if (props.height > 0) return props.height
  return isMobile.value ? 420 : 520
})

const reducedMotion = ref(prefersReducedMotion())
const autoRotate = ref(!reducedMotion.value)

// Camera spherical orbit state (lat/lon of camera target look-at point)
let targetLon = 105
let targetLat = 24
let currentLon = 105
let currentLat = 24
let targetDist = DEFAULT_DIST_LANDSCAPE
let currentDist = DEFAULT_DIST_LANDSCAPE
let defaultDist = DEFAULT_DIST_LANDSCAPE
let velLon = 0
let velLat = 0
let hasInitialFocus = false

// Quantized zoomLevel in [0, 1] for deterministic cluster spread expansion on zoom
const zoomSpreadBucket = ref(0)
function distToZoomLevel(d: number): number {
  return Math.max(0, Math.min(1, (defaultDist - d) / Math.max(0.1, defaultDist - MIN_DIST)))
}

/** World-size factor for markers at camera distance `d`: it follows the camera's height above the
 *  surface, so a marker keeps about its screen size, plus {@link MARKER_ZOOM_GROWTH}. */
function markerScaleFor(d: number): number {
  const h = Math.max(0.05, d - 1) / Math.max(0.05, defaultDist - 1)
  return Math.min(1.25, Math.pow(h, 1 - MARKER_ZOOM_GROWTH))
}

// Selection & hover state
const hoveredNodeId = ref<string | null>(null)
const selectedNodeId = ref<string | null>(null)
const hoveredArcKey = ref<string | null>(null)
const selectedArcKey = ref<string | null>(null)
const pointerPos = ref<{ x: number; y: number } | null>(null)

const layout = computed(() =>
  placeGlobeNodes(props.nodes, props.showControlPlane ? props.center : null, zoomSpreadBucket.value),
)
const placedNodes = computed<PlacedGlobeNode[]>(() => layout.value.nodes)
const placedCenter = computed<PlacedGlobeCenter | null>(() => layout.value.center)

// Include subtle control-plane spokes when showControlPlane is enabled
const effectiveArcs = computed<GlobeArc[]>(() => {
  const list = [...props.arcs]
  if (props.showControlPlane && placedCenter.value) {
    const cid = placedCenter.value.id
    for (const n of placedNodes.value) {
      if (n.isCentre) continue
      list.push({
        key: `ctrl:${n.id}`,
        from: n.id,
        to: cid,
        carrier: 'control',
        color: palette.value.controlSpoke,
        dashed: !n.online,
        kind: 'control',
      })
    }
  }
  return list
})

const selectedNode = computed<PlacedGlobeNode | null>(() => {
  if (!selectedNodeId.value) return null
  if (placedCenter.value && selectedNodeId.value === placedCenter.value.id) {
    return {
      id: placedCenter.value.id,
      name: placedCenter.value.name,
      online: true,
      presence: 'online',
      role: 'centre',
      isCentre: true,
      baseLon: placedCenter.value.lon,
      baseLat: placedCenter.value.lat,
      lon: placedCenter.value.lon,
      lat: placedCenter.value.lat,
      precision: placedCenter.value.orbital ? 'unknown' : 'country',
      locationLabel: placedCenter.value.locationLabel ?? '',
      clusterSize: 1,
      clusterIndex: 0,
    }
  }
  return placedNodes.value.find((n) => n.id === selectedNodeId.value) ?? null
})

const selectedArc = computed<GlobeArc | null>(() => {
  if (!selectedArcKey.value) return null
  return effectiveArcs.value.find((a) => a.key === selectedArcKey.value) ?? null
})

interface ProjectedLabel {
  id: string
  text: string
  x: number
  y: number
  color: string
  isCentre: boolean
  isGateway: boolean
  active: boolean
}
const visibleLabels = shallowRef<ProjectedLabel[]>([])

const hoverTip = computed(() => {
  if (!pointerPos.value) return null
  const W = stageWidth.value
  const H = stageHeight.value
  const clampPos = (px: number, py: number) => ({
    x: Math.min(Math.max(12, px + 14), Math.max(12, W - 230)),
    y: Math.min(Math.max(12, py - 14), Math.max(12, H - 72)),
  })

  if (hoveredNodeId.value) {
    // Don't double-render a tooltip directly over the already-pinned node.
    if (hoveredNodeId.value === selectedNodeId.value) return null
    if (placedCenter.value && hoveredNodeId.value === placedCenter.value.id) {
      const pos = clampPos(pointerPos.value.x, pointerPos.value.y)
      return {
        ...pos,
        title: placedCenter.value.name,
        subtitle: t('mh.mesh.role.centre'),
        color: palette.value.centreColor,
      }
    }
    const n = placedNodes.value.find((x) => x.id === hoveredNodeId.value)
    if (!n) return null
    const bits: string[] = []
    if (n.zoneName) bits.push(n.zoneName)
    if (n.isGateway) bits.push(t('mh.mesh.role.gateway'))
    bits.push(n.online ? t('mh.mesh.status.online') : t('mh.mesh.status.offline'))
    if (n.locationLabel) bits.push(n.locationLabel)
    const pos = clampPos(pointerPos.value.x, pointerPos.value.y)
    return {
      ...pos,
      title: n.name,
      subtitle: bits.join(' · '),
      color: nodeDotColor(n),
    }
  }

  if (hoveredArcKey.value) {
    if (hoveredArcKey.value === selectedArcKey.value) return null
    const a = effectiveArcs.value.find((x) => x.key === hoveredArcKey.value)
    if (!a || a.kind === 'control') return null
    const fromN = placedNodes.value.find((x) => x.id === a.from)
    const toN = placedNodes.value.find((x) => x.id === a.to)
    if (!fromN || !toN) return null
    const bits = [
      a.ends?.[0] ? qualifiedCarrier(a.ends[0].carrier, a.ends[0].relay) : a.carrier,
    ]
    if (a.rttMs != null) bits.push(`${a.rttMs} ms`)
    if (a.stalled) bits.push(t('mh.mesh.stalled'))
    const pos = clampPos(pointerPos.value.x, pointerPos.value.y)
    return {
      ...pos,
      title: `${fromN.name} ↔ ${toN.name}`,
      subtitle: bits.join(' · '),
      color: a.color,
    }
  }
  return null
})

function nodeDotColor(n: PlacedGlobeNode): string {
  if (n.color) return n.color
  if (n.isCentre) return palette.value.centreColor
  const pres = n.presence ?? (n.online ? 'online' : 'offline')
  if (pres === 'online') return palette.value.nodeOnline
  if (pres === 'stale') return palette.value.nodeStale
  return palette.value.nodeOffline
}

// ── Three.js scene objects (non-reactive for zero Vue overhead in rAF) ────────
let renderer: WebGLRenderer | null = null
let scene: Scene | null = null
let camera: PerspectiveCamera | null = null
let globeGroup: Group | null = null
let earthMesh: Mesh | null = null
let earthTexture: CanvasTexture | null = null
let earthMaterial: MeshPhongMaterial | null = null
let ambientLight: AmbientLight | null = null
let sunLight: DirectionalLight | null = null
let coastLines: LineSegments | null = null
let borderLines: LineSegments | null = null
let innerAtmoMesh: Mesh | null = null
let outerAtmoMesh: Mesh | null = null
let innerAtmoMat: ShaderMaterial | null = null
let outerAtmoMat: ShaderMaterial | null = null
let arcLines: LineSegments | null = null
let arcGeometry: BufferGeometry | null = null
let arcMaterial: ShaderMaterial | null = null
let nodeCoreMesh: InstancedMesh | null = null
let nodeRingMesh: InstancedMesh | null = null
let centreGroup: Group | null = null
let centreBeacon: Mesh | null = null
let centreRing: Mesh | null = null
/** Per-instance marker data, so a zoom rewrites the matrices without rebuilding the meshes. */
interface MarkerInstance {
  normal: Vector3
  quat: Quaternion
  core: number
  ring: number
}
let markerInstances: MarkerInstance[] = []
let markerScale = 1
let rafId = 0
let resizeObs: ResizeObserver | null = null
let disposed = false
let worldTopoCache: Awaited<ReturnType<typeof loadWorldTopology>> | null = null

// Cached 3D positions & sampled arc vertices for fast 2D screen-space picking
interface CachedArcPick {
  key: string
  samples: Vector3[]
  isControl: boolean
}
let cachedNodePositions = new Map<string, Vector3>()
let cachedArcPicks: CachedArcPick[] = []
let arcVertexRanges: Array<{ key: string; startVert: number; vertCount: number }> = []

function initScene(): boolean {
  const canvas = canvasEl.value
  const stage = stageEl.value
  if (!canvas || !stage) return false

  try {
    renderer = new WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    })
  } catch (err) {
    emit('webgl-error', err instanceof Error ? err.message : 'WebGL2 init failed')
    return false
  }

  const w = Math.max(200, stage.clientWidth || 640)
  stageWidth.value = w
  const h = stageHeight.value
  defaultDist = computeDefaultDist(w, h)
  targetDist = defaultDist
  currentDist = defaultDist
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
  renderer.setSize(w, h, false)

  scene = new Scene()
  camera = new PerspectiveCamera(38, w / h, 0.1, 40)
  camera.position.set(0, 0, defaultDist)

  const pal = palette.value
  ambientLight = new AmbientLight(pal.ambientHex, pal.ambientIntensity)
  scene.add(ambientLight)

  sunLight = new DirectionalLight(0xffffff, pal.sunIntensity)
  sunLight.position.set(3.5, 2.2, 4.2)
  scene.add(sunLight)

  globeGroup = new Group()
  scene.add(globeGroup)

  // Base Earth sphere (initially painted with ocean color until Natural Earth resolves)
  earthMaterial = new MeshPhongMaterial({
    color: new Color(pal.oceanMid),
    shininess: 14,
    specular: new Color(pal.specular),
  })
  earthMesh = new Mesh(new SphereGeometry(1, 72, 72), earthMaterial)
  globeGroup.add(earthMesh)

  // Inner limb Fresnel glow (crisp Stripe/MapLibre-like atmospheric horizon on Earth rim)
  innerAtmoMat = new ShaderMaterial({
    transparent: true,
    side: FrontSide,
    depthWrite: false,
    blending: NormalBlending,
    uniforms: {
      uColor: { value: new Color(pal.atmosphereInner) },
      uIntensity: { value: pal.isDark ? 0.55 : 0.24 },
    },
    vertexShader: `
      varying vec3 vNormal;
      varying vec3 vViewDir;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        vec4 mv = modelViewMatrix * vec4(position, 1.0);
        vViewDir = normalize(-mv.xyz);
        gl_Position = projectionMatrix * mv;
      }
    `,
    fragmentShader: `
      uniform vec3 uColor;
      uniform float uIntensity;
      varying vec3 vNormal;
      varying vec3 vViewDir;
      void main() {
        float ndv = clamp(dot(normalize(vNormal), normalize(vViewDir)), 0.0, 1.0);
        float rim = pow(1.0 - ndv, 3.8);
        gl_FragColor = vec4(uColor, rim * uIntensity);
      }
    `,
  })
  innerAtmoMesh = new Mesh(new SphereGeometry(1.006, 64, 64), innerAtmoMat)
  globeGroup.add(innerAtmoMesh)

  // Outer atmospheric halo (BackSide with strict 0.0 fade at silhouette — zero hard ring!)
  outerAtmoMat = new ShaderMaterial({
    transparent: true,
    side: BackSide,
    depthWrite: false,
    blending: NormalBlending,
    uniforms: {
      uColor: { value: new Color(pal.atmosphereOuter) },
      uIntensity: { value: pal.atmosphereIntensity },
    },
    vertexShader: `
      varying vec3 vNormal;
      varying vec3 vViewDir;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        vec4 mv = modelViewMatrix * vec4(position, 1.0);
        vViewDir = normalize(-mv.xyz);
        gl_Position = projectionMatrix * mv;
      }
    `,
    fragmentShader: `
      uniform vec3 uColor;
      uniform float uIntensity;
      varying vec3 vNormal;
      varying vec3 vViewDir;
      void main() {
        float inner = clamp(dot(-normalize(vNormal), normalize(vViewDir)), 0.0, 1.0);
        float glow = pow(inner, 4.4) * uIntensity;
        gl_FragColor = vec4(uColor, glow);
      }
    `,
  })
  outerAtmoMesh = new Mesh(new SphereGeometry(1.15, 56, 56), outerAtmoMat)
  globeGroup.add(outerAtmoMesh)

  // Async load self-hosted Natural Earth 1:50m TopoJSON
  void loadWorldTopology().then((topo) => {
    if (disposed || !globeGroup || !earthMaterial) return
    worldTopoCache = topo
    applyEarthAppearance()
  })

  return true
}

function applyEarthAppearance() {
  if (!globeGroup || !earthMaterial || !ambientLight || !sunLight || !innerAtmoMat || !outerAtmoMat) {
    return
  }
  const pal = palette.value
  ambientLight.color.setHex(pal.ambientHex)
  ambientLight.intensity = pal.ambientIntensity
  sunLight.intensity = pal.sunIntensity
  earthMaterial.specular.set(pal.specular)
  innerAtmoMat.uniforms.uColor!.value.set(pal.atmosphereInner)
  innerAtmoMat.uniforms.uIntensity!.value = pal.isDark ? 0.52 : 0.22
  outerAtmoMat.uniforms.uColor!.value.set(pal.atmosphereOuter)
  outerAtmoMat.uniforms.uIntensity!.value = pal.atmosphereIntensity

  if (!worldTopoCache) return

  // Dispose old texture & bake crisp theme-matched Earth canvas texture
  earthTexture?.dispose()
  earthTexture = createEarthCanvasTexture(worldTopoCache, pal, !isMobile.value)
  earthMaterial.color.setHex(0xffffff)
  earthMaterial.map = earthTexture
  earthMaterial.needsUpdate = true

  // Build vector coastline & border LineSegments once; re-colour on theme flip
  if (!coastLines || !borderLines) {
    const vecs = createVectorBorderGeometries(worldTopoCache, 1.0022)
    coastLines = new LineSegments(
      vecs.coastlines,
      new LineBasicMaterial({
        color: new Color(pal.vectorCoast),
        transparent: true,
        opacity: pal.isDark ? 0.42 : 0.34,
        depthWrite: false,
      }),
    )
    borderLines = new LineSegments(
      vecs.borders,
      new LineBasicMaterial({
        color: new Color(pal.vectorBorder),
        transparent: true,
        opacity: pal.isDark ? 0.32 : 0.38,
        depthWrite: false,
      }),
    )
    globeGroup.add(borderLines)
    globeGroup.add(coastLines)
  } else {
    const cMat = coastLines.material as LineBasicMaterial
    cMat.color.set(pal.vectorCoast)
    cMat.opacity = pal.isDark ? 0.42 : 0.34
    const bMat = borderLines.material as LineBasicMaterial
    bMat.color.set(pal.vectorBorder)
    bMat.opacity = pal.isDark ? 0.32 : 0.38
  }
}

function disposeMesh(obj: Mesh | LineSegments | InstancedMesh | null) {
  if (!obj) return
  obj.parent?.remove(obj)
  obj.geometry.dispose()
  if (Array.isArray(obj.material)) obj.material.forEach((m) => m.dispose())
  else obj.material.dispose()
}

function rebuildNodesAndCentre() {
  if (!globeGroup) return
  disposeMesh(nodeCoreMesh)
  disposeMesh(nodeRingMesh)
  nodeCoreMesh = null
  nodeRingMesh = null
  if (centreGroup) {
    centreGroup.traverse((child) => {
      if ((child as Mesh).geometry) (child as Mesh).geometry.dispose()
      const mat = (child as Mesh).material
      if (Array.isArray(mat)) mat.forEach((m) => m.dispose())
      else if (mat) mat.dispose()
    })
    centreGroup.parent?.remove(centreGroup)
    centreGroup = null
  }
  centreBeacon = null
  centreRing = null
  markerInstances = []

  cachedNodePositions = new Map()
  const list = placedNodes.value
  const pal = palette.value

  // Instanced device node beacons (1 draw call for cores + 1 for tangent halo rings)
  if (list.length > 0) {
    const coreGeo = new SphereGeometry(NODE_CORE_R, 16, 16)
    const coreMat = new MeshBasicMaterial({ color: 0xffffff })
    nodeCoreMesh = new InstancedMesh(coreGeo, coreMat, list.length)

    const ringGeo = new RingGeometry(NODE_RING_IN, NODE_RING_OUT, 24)
    const ringMat = new MeshBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: pal.isDark ? 0.72 : 0.62,
      side: 2, // DoubleSide
      depthWrite: false,
    })
    nodeRingMesh = new InstancedMesh(ringGeo, ringMat, list.length)

    const zAxis = new Vector3(0, 0, 1)
    markerInstances = []

    list.forEach((n, idx) => {
      const p = latLonToVec3(n.lat, n.lon, 1 + NODE_CORE_LIFT)
      const vec = new Vector3(p.x, p.y, p.z)
      cachedNodePositions.set(n.id, vec)

      const isActive = selectedNodeId.value === n.id || hoveredNodeId.value === n.id || n.pending
      const coreScale = isActive ? 1.48 : n.isGateway || n.isEntry ? 1.24 : n.online ? 1.0 : 0.82
      const col = new Color(nodeDotColor(n))
      nodeCoreMesh!.setColorAt(idx, col)

      // The halo ring lies tangent to the sphere, facing out along the normal.
      const normal = vec.clone().normalize()
      const ringScale = isActive ? 1.65 : n.isGateway || n.isEntry ? 1.38 : n.online ? 1.02 : 0.65
      markerInstances.push({
        normal,
        quat: new Quaternion().setFromUnitVectors(zAxis, normal),
        core: coreScale,
        ring: ringScale,
      })
      nodeRingMesh!.setColorAt(
        idx,
        new Color(isActive ? pal.centreRing : n.isGateway ? pal.centreRing : nodeDotColor(n)),
      )
    })

    if (nodeCoreMesh.instanceColor) nodeCoreMesh.instanceColor.needsUpdate = true
    if (nodeRingMesh.instanceColor) nodeRingMesh.instanceColor.needsUpdate = true
    globeGroup.add(nodeRingMesh)
    globeGroup.add(nodeCoreMesh)
  }

  // Distinct Centre Beacon (elevated teal diamond + crisp orbital accent ring)
  if (placedCenter.value) {
    const c = placedCenter.value
    const r = c.orbital ? 1.075 : 1.024
    const p = latLonToVec3(c.lat, c.lon, r)
    const vec = new Vector3(p.x, p.y, p.z)
    cachedNodePositions.set(c.id, vec)

    centreGroup = new Group()
    centreGroup.position.copy(vec)
    const normal = vec.clone().normalize()
    const quat = new Quaternion().setFromUnitVectors(new Vector3(0, 0, 1), normal)

    const beacon = new Mesh(
      new OctahedronGeometry(CENTRE_BEACON_R, 0),
      new MeshBasicMaterial({ color: new Color(pal.centreColor) }),
    )
    centreGroup.add(beacon)
    centreBeacon = beacon

    const outerRing = new Mesh(
      new RingGeometry(CENTRE_RING_IN, CENTRE_RING_OUT, 32),
      new MeshBasicMaterial({
        color: new Color(pal.centreRing),
        transparent: true,
        opacity: 0.9,
        side: 2,
        depthWrite: false,
      }),
    )
    outerRing.quaternion.copy(quat)
    centreGroup.add(outerRing)
    centreRing = outerRing

    // Subtle vertical tether from Earth surface up to orbital centre hub
    if (c.orbital) {
      const surfaceP = latLonToVec3(c.lat, c.lon, 1.003)
      const tetherGeo = new BufferGeometry().setFromPoints([
        new Vector3(0, 0, 0),
        new Vector3(surfaceP.x - p.x, surfaceP.y - p.y, surfaceP.z - p.z),
      ])
      centreGroup.add(
        new LineSegments(
          tetherGeo,
          new LineBasicMaterial({
            color: new Color(pal.centreColor),
            transparent: true,
            opacity: 0.45,
          }),
        ),
      )
    }

    globeGroup.add(centreGroup)
  }

  applyMarkerScale(markerScaleFor(currentDist))

  // Orient initial camera toward the fleet centroid once on first data arrival
  if (!hasInitialFocus && (list.length > 0 || placedCenter.value)) {
    const focus = placedCenter.value ?? list[0]!
    targetLon = focus.lon
    targetLat = Math.max(-45, Math.min(45, focus.lat))
    currentLon = targetLon
    currentLat = targetLat
    hasInitialFocus = true
  }
}

/** Size every marker for world-size factor `m` ({@link markerScaleFor}); also lowers the lift, so
 *  a small marker up close still sits on its place rather than floating above it. */
function applyMarkerScale(m: number) {
  markerScale = m
  if (nodeCoreMesh && nodeRingMesh) {
    const mtx = new Matrix4()
    const pos = new Vector3()
    const scale = new Vector3()
    const noTurn = new Quaternion()
    markerInstances.forEach((inst, idx) => {
      pos.copy(inst.normal).multiplyScalar(1 + NODE_CORE_LIFT * m)
      mtx.compose(pos, noTurn, scale.setScalar(inst.core * m))
      nodeCoreMesh!.setMatrixAt(idx, mtx)
      pos.copy(inst.normal).multiplyScalar(1 + Math.max(0.0015, NODE_RING_LIFT * m))
      mtx.compose(pos, inst.quat, scale.set(inst.ring * m, inst.ring * m, 1))
      nodeRingMesh!.setMatrixAt(idx, mtx)
    })
    nodeCoreMesh.instanceMatrix.needsUpdate = true
    nodeRingMesh.instanceMatrix.needsUpdate = true
  }
  centreBeacon?.scale.setScalar(m)
  centreRing?.scale.setScalar(m)
}

function rebuildArcs() {
  if (!globeGroup) return
  disposeMesh(arcLines)
  arcLines = null
  arcGeometry = null
  arcMaterial = null
  cachedArcPicks = []
  arcVertexRanges = []

  const arcs = effectiveArcs.value
  const nodeMap = new Map(placedNodes.value.map((n) => [n.id, n]))
  const centerNode = placedCenter.value

  interface ResolvedArc {
    arc: GlobeArc
    pts: Array<{ x: number; y: number; z: number }>
  }
  const resolved: ResolvedArc[] = []

  for (const arc of arcs) {
    const a = nodeMap.get(arc.from)
    const b =
      nodeMap.get(arc.to) ??
      (centerNode && arc.to === centerNode.id
        ? { lat: centerNode.lat, lon: centerNode.lon, orbital: centerNode.orbital }
        : undefined)
    if (!a || !b) continue
    const isCtrl = arc.kind === 'control'
    const segs = isCtrl ? 18 : ARC_SEGMENTS
    const endRadius = 'orbital' in b && b.orbital ? 1.075 : 1.01
    const rawPts = buildGreatCircleArcPoints(
      a.lat,
      a.lon,
      b.lat,
      b.lon,
      segs,
      1.01,
      isCtrl ? 0.01 : 0,
    )
    // Lift the final leg smoothly to the orbital centre hub if applicable
    if (isCtrl && endRadius > 1.02) {
      for (let i = 0; i < rawPts.length; i++) {
        const t = i / (rawPts.length - 1)
        const lift = 1 + t * t * (endRadius - 1.01)
        rawPts[i] = {
          x: rawPts[i]!.x * lift,
          y: rawPts[i]!.y * lift,
          z: rawPts[i]!.z * lift,
        }
      }
    }
    resolved.push({ arc, pts: rawPts })
  }

  if (!resolved.length) return

  let totalVerts = 0
  for (const r of resolved) totalVerts += (r.pts.length - 1) * 2

  const positions = new Float32Array(totalVerts * 3)
  const fromColors = new Float32Array(totalVerts * 3)
  const toColors = new Float32Array(totalVerts * 3)
  const progress = new Float32Array(totalVerts)
  const phases = new Float32Array(totalVerts)
  const dashed = new Float32Array(totalVerts)
  const opacities = new Float32Array(totalVerts)
  const pulses = new Float32Array(totalVerts)

  const states = computeArcVisualStates(
    resolved.map((r) => r.arc),
    {
      hoveredNodeId: hoveredNodeId.value,
      selectedNodeId: selectedNodeId.value,
      hoveredArcKey: hoveredArcKey.value,
      selectedArcKey: selectedArcKey.value,
    },
  )

  let ptr = 0
  resolved.forEach(({ arc, pts }, idx) => {
    const st = states[idx]!
    const cFrom = new Color(arc.fromColor ?? arc.color)
    const cTo = new Color(arc.toColor ?? arc.color)
    const phase = (idx * 0.6180339887) % 1
    const isDash = st.dashed ? 1 : 0
    const startVert = ptr
    const segCount = pts.length - 1

    // Keep 9 lightweight 3D pick samples along each peer arc
    if (arc.kind !== 'control') {
      const samples: Vector3[] = []
      for (let k = 0; k <= 8; k++) {
        const p = pts[Math.round((k / 8) * segCount)]!
        samples.push(new Vector3(p.x, p.y, p.z))
      }
      cachedArcPicks.push({ key: arc.key, samples, isControl: false })
    }

    for (let s = 0; s < segCount; s++) {
      const p0 = pts[s]!
      const p1 = pts[s + 1]!
      const t0 = s / segCount
      const t1 = (s + 1) / segCount

      for (const [pt, prog] of [
        [p0, t0],
        [p1, t1],
      ] as const) {
        positions[ptr * 3] = pt.x
        positions[ptr * 3 + 1] = pt.y
        positions[ptr * 3 + 2] = pt.z
        fromColors[ptr * 3] = cFrom.r
        fromColors[ptr * 3 + 1] = cFrom.g
        fromColors[ptr * 3 + 2] = cFrom.b
        toColors[ptr * 3] = cTo.r
        toColors[ptr * 3 + 1] = cTo.g
        toColors[ptr * 3 + 2] = cTo.b
        progress[ptr] = prog
        phases[ptr] = phase
        dashed[ptr] = isDash
        opacities[ptr] = st.opacity
        pulses[ptr] = st.pulseStrength
        ptr++
      }
    }
    arcVertexRanges.push({ key: arc.key, startVert, vertCount: ptr - startVert })
  })

  arcGeometry = new BufferGeometry()
  arcGeometry.setAttribute('position', new BufferAttribute(positions, 3))
  arcGeometry.setAttribute('aFromColor', new BufferAttribute(fromColors, 3))
  arcGeometry.setAttribute('aToColor', new BufferAttribute(toColors, 3))
  arcGeometry.setAttribute('aProgress', new BufferAttribute(progress, 1))
  arcGeometry.setAttribute('aPhase', new BufferAttribute(phases, 1))
  arcGeometry.setAttribute('aDashed', new BufferAttribute(dashed, 1))
  arcGeometry.setAttribute('aOpacity', new BufferAttribute(opacities, 1))
  arcGeometry.setAttribute('aPulse', new BufferAttribute(pulses, 1))

  arcMaterial = new ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: NormalBlending,
    uniforms: {
      uTime: { value: 0 },
      uMotion: { value: reducedMotion.value ? 0 : 1 },
      uIsDark: { value: isDark.value ? 1 : 0 },
    },
    vertexShader: `
      attribute vec3 aFromColor;
      attribute vec3 aToColor;
      attribute float aProgress;
      attribute float aPhase;
      attribute float aDashed;
      attribute float aOpacity;
      attribute float aPulse;
      varying vec3 vColor;
      varying float vProgress;
      varying float vPhase;
      varying float vDashed;
      varying float vOpacity;
      varying float vPulse;
      void main() {
        float mixT = smoothstep(0.42, 0.58, aProgress);
        vColor = mix(aFromColor, aToColor, mixT);
        vProgress = aProgress;
        vPhase = aPhase;
        vDashed = aDashed;
        vOpacity = aOpacity;
        vPulse = aPulse;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform float uTime;
      uniform float uMotion;
      uniform float uIsDark;
      varying vec3 vColor;
      varying float vProgress;
      varying float vPhase;
      varying float vDashed;
      varying float vOpacity;
      varying float vPulse;
      void main() {
        if (vOpacity < 0.01) discard;
        if (vDashed > 0.5 && fract(vProgress * 18.0) > 0.54) discard;
        float pulse = 0.0;
        if (uMotion > 0.5 && vPulse > 0.01) {
          float head = fract(uTime * 0.24 + vPhase);
          float dist = fract(head - vProgress);
          pulse = exp(-dist * 11.0) * vPulse;
        }
        vec3 highlight = mix(vColor, vec3(1.0), uIsDark > 0.5 ? 0.35 : 0.12);
        vec3 col = mix(vColor, highlight, pulse * 0.65);
        float alpha = clamp(vOpacity + pulse * (uIsDark > 0.5 ? 0.62 : 0.45), 0.0, 1.0);
        gl_FragColor = vec4(col, alpha);
      }
    `,
  })

  arcLines = new LineSegments(arcGeometry, arcMaterial)
  globeGroup.add(arcLines)
}

/** Fast O(V) attribute update on hover/select without rebuilding 3D geometry. */
function updateArcFocusAttributes() {
  if (!arcGeometry || !arcVertexRanges.length) return
  const states = computeArcVisualStates(effectiveArcs.value, {
    hoveredNodeId: hoveredNodeId.value,
    selectedNodeId: selectedNodeId.value,
    hoveredArcKey: hoveredArcKey.value,
    selectedArcKey: selectedArcKey.value,
  })
  const stateByKey = new Map(states.map((s) => [s.key, s]))
  const opAttr = arcGeometry.getAttribute('aOpacity') as BufferAttribute
  const puAttr = arcGeometry.getAttribute('aPulse') as BufferAttribute
  const opArr = opAttr.array as Float32Array
  const puArr = puAttr.array as Float32Array
  for (const r of arcVertexRanges) {
    const st = stateByKey.get(r.key)
    const op = st?.opacity ?? 0.2
    const pu = st?.pulseStrength ?? 0
    opArr.fill(op, r.startVert, r.startVert + r.vertCount)
    puArr.fill(pu, r.startVert, r.startVert + r.vertCount)
  }
  opAttr.needsUpdate = true
  puAttr.needsUpdate = true
}

// ── Camera & 2D Screen-Space Projection + Collision-Culled Labels ─────────────
const tmpVec = new Vector3()
const camPos = new Vector3()

function syncCameraPosition() {
  if (!camera) return
  const p = latLonToVec3(currentLat, currentLon, currentDist)
  camera.position.set(p.x, p.y, p.z)
  camera.lookAt(0, 0, 0)
}

function projectToScreen(worldPos: Vector3): { x: number; y: number; visible: boolean } {
  if (!camera) return { x: 0, y: 0, visible: false }
  camPos.copy(camera.position)
  // Front-hemisphere visibility check (dot with outward normal > horizon threshold)
  const dirToCam = camPos.clone().sub(worldPos).normalize()
  const normal = worldPos.clone().normalize()
  if (normal.dot(dirToCam) < 0.08) return { x: 0, y: 0, visible: false }

  tmpVec.copy(worldPos).project(camera)
  if (tmpVec.z > 1) return { x: 0, y: 0, visible: false }
  const w = stageWidth.value
  const h = stageHeight.value
  return {
    x: (tmpVec.x * 0.5 + 0.5) * w,
    y: (-tmpVec.y * 0.5 + 0.5) * h,
    visible: true,
  }
}

let lastLabelFrame = 0
function updateProjectedLabels(nowMs: number) {
  if (nowMs - lastLabelFrame < 55) return
  lastLabelFrame = nowMs
  if (!camera) return

  const candidates: Array<ProjectedLabel & { priority: number }> = []
  const zoom = distToZoomLevel(currentDist)
  const maxLabels = isMobile.value ? (zoom > 0.45 ? 10 : 6) : zoom > 0.45 ? 18 : 10

  if (placedCenter.value) {
    const pos = cachedNodePositions.get(placedCenter.value.id)
    if (pos) {
      const sp = projectToScreen(pos)
      if (sp.visible) {
        candidates.push({
          id: placedCenter.value.id,
          text: placedCenter.value.name,
          x: Math.round(sp.x),
          y: Math.round(sp.y - 16),
          color: palette.value.centreColor,
          isCentre: true,
          isGateway: false,
          active:
            selectedNodeId.value === placedCenter.value.id ||
            hoveredNodeId.value === placedCenter.value.id,
          priority: 100,
        })
      }
    }
  }

  for (const n of placedNodes.value) {
    const pos = cachedNodePositions.get(n.id)
    if (!pos) continue
    const sp = projectToScreen(pos)
    if (!sp.visible) continue
    const active = selectedNodeId.value === n.id || hoveredNodeId.value === n.id
    const isGw = Boolean(n.isGateway || n.isEntry)
    const priority = active ? 200 : isGw ? 80 : n.online ? 40 : 15
    candidates.push({
      id: n.id,
      text: n.name,
      x: Math.round(sp.x),
      y: Math.round(sp.y - 14),
      color: nodeDotColor(n),
      isCentre: Boolean(n.isCentre),
      isGateway: isGw,
      active,
      priority,
    })
  }

  candidates.sort((a, b) => b.priority - a.priority || a.text.localeCompare(b.text))

  // Greedy 2D AABB collision culling so labels never stack over each other or the HUD
  const placedBoxes: Array<{ x1: number; y1: number; x2: number; y2: number }> = [
    { x1: 0, y1: 0, x2: 58, y2: 142 },
  ]
  const out: ProjectedLabel[] = []
  const W = stageWidth.value
  const H = stageHeight.value

  for (const c of candidates) {
    if (out.length >= maxLabels && !c.active) break
    if (c.x < 18 || c.x > W - 18 || c.y < 14 || c.y > H - 24) continue
    const estW = Math.min(148, c.text.length * 6.8 + 26)
    const box = { x1: c.x - estW / 2, y1: c.y - 11, x2: c.x + estW / 2, y2: c.y + 11 }
    const collides = placedBoxes.some(
      (b) => !(box.x2 + 6 < b.x1 || box.x1 - 6 > b.x2 || box.y2 + 4 < b.y1 || box.y1 - 4 > b.y2),
    )
    if (collides && !c.active) continue
    placedBoxes.push(box)
    out.push(c)
  }
  visibleLabels.value = out
}

// ── Generous 2D Screen-Space Picking (Nodes + 3D Arcs) ────────────────────────
function pointToSegmentDistSq(
  px: number,
  py: number,
  ax: number,
  ay: number,
  bx: number,
  by: number,
): number {
  const dx = bx - ax
  const dy = by - ay
  const lenSq = dx * dx + dy * dy
  if (lenSq < 1e-4) return (px - ax) ** 2 + (py - ay) ** 2
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lenSq))
  const cx = ax + t * dx
  const cy = ay + t * dy
  return (px - cx) ** 2 + (py - cy) ** 2
}

function pickAt(clientX: number, clientY: number): { nodeId: string | null; arcKey: string | null } {
  const el = canvasEl.value
  if (!el || !camera) return { nodeId: null, arcKey: null }
  const rect = el.getBoundingClientRect()
  const x = clientX - rect.left
  const y = clientY - rect.top

  const nodeHitR = isMobile.value ? 22 : 16
  let bestNode: string | null = null
  let bestNodeDist = nodeHitR * nodeHitR

  for (const [id, vec] of cachedNodePositions) {
    const sp = projectToScreen(vec)
    if (!sp.visible) continue
    const d2 = (sp.x - x) ** 2 + (sp.y - y) ** 2
    if (d2 < bestNodeDist) {
      bestNodeDist = d2
      bestNode = id
    }
  }
  if (bestNode) return { nodeId: bestNode, arcKey: null }

  const arcHitR = isMobile.value ? 15 : 10
  let bestArc: string | null = null
  let bestArcDist = arcHitR * arcHitR

  for (const ap of cachedArcPicks) {
    let prev: { x: number; y: number; visible: boolean } | null = null
    for (const s of ap.samples) {
      const sp = projectToScreen(s)
      if (prev?.visible && sp.visible) {
        const d2 = pointToSegmentDistSq(x, y, prev.x, prev.y, sp.x, sp.y)
        if (d2 < bestArcDist) {
          bestArcDist = d2
          bestArc = ap.key
        }
      }
      prev = sp
    }
  }
  return { nodeId: null, arcKey: bestArc }
}

// ── Pointer, Touch Pinch-to-Zoom, Wheel, and Keyboard Interaction ────────────
const activePointers = new Map<number, { x: number; y: number }>()
let dragStartPos: { x: number; y: number } | null = null
let dragMoved = false
let lastPinchDist = 0

function pauseIdleRotation() {
  autoRotate.value = false
}

function onPointerDown(e: PointerEvent) {
  pauseIdleRotation()
  ;(e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId)
  activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
  if (activePointers.size === 1) {
    dragStartPos = { x: e.clientX, y: e.clientY }
    dragMoved = false
    velLon = 0
    velLat = 0
  } else if (activePointers.size === 2) {
    const pts = [...activePointers.values()]
    lastPinchDist = Math.hypot(pts[0]!.x - pts[1]!.x, pts[0]!.y - pts[1]!.y)
    dragMoved = true
  }
}

function onPointerMove(e: PointerEvent) {
  const rect = canvasEl.value?.getBoundingClientRect()
  if (rect) {
    pointerPos.value = { x: e.clientX - rect.left, y: e.clientY - rect.top }
  }

  if (activePointers.has(e.pointerId)) {
    const prev = activePointers.get(e.pointerId)!
    activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY })

    if (activePointers.size === 2) {
      const pts = [...activePointers.values()]
      const dist = Math.hypot(pts[0]!.x - pts[1]!.x, pts[0]!.y - pts[1]!.y)
      if (lastPinchDist > 0) {
        const delta = (lastPinchDist - dist) * 0.0085
        targetDist = Math.max(MIN_DIST, Math.min(MAX_DIST, targetDist + delta))
      }
      lastPinchDist = dist
      return
    }

    const dx = e.clientX - prev.x
    const dy = e.clientY - prev.y
    if (dragStartPos && Math.hypot(e.clientX - dragStartPos.x, e.clientY - dragStartPos.y) > 5) {
      dragMoved = true
    }
    const sens = 0.24 * (currentDist / defaultDist)
    targetLon -= dx * sens
    targetLat = Math.max(-78, Math.min(78, targetLat + dy * sens))
    velLon = -dx * sens * 0.55
    velLat = dy * sens * 0.55
    return
  }

  // Hover picking (mouse pointer only)
  if (e.pointerType === 'mouse') {
    const hit = pickAt(e.clientX, e.clientY)
    if (hit.nodeId !== hoveredNodeId.value || hit.arcKey !== hoveredArcKey.value) {
      hoveredNodeId.value = hit.nodeId
      hoveredArcKey.value = hit.arcKey
      updateArcFocusAttributes()
      if (canvasEl.value) {
        canvasEl.value.style.cursor = hit.nodeId || hit.arcKey ? 'pointer' : 'grab'
      }
    }
  }
}

function onPointerUp(e: PointerEvent) {
  const wasSingle = activePointers.size === 1 && activePointers.has(e.pointerId)
  activePointers.delete(e.pointerId)
  if (activePointers.size < 2) lastPinchDist = 0

  if (wasSingle && !dragMoved) {
    const hit = pickAt(e.clientX, e.clientY)
    if (hit.nodeId) {
      selectedArcKey.value = null
      selectedNodeId.value = selectedNodeId.value === hit.nodeId ? null : hit.nodeId
      emit('node-click', hit.nodeId)
    } else if (hit.arcKey) {
      selectedNodeId.value = null
      selectedArcKey.value = selectedArcKey.value === hit.arcKey ? null : hit.arcKey
      emit('arc-click', hit.arcKey)
    } else {
      clearSelection()
    }
    updateArcFocusAttributes()
    rebuildNodesAndCentre()
  }
}

function onPointerLeave() {
  pointerPos.value = null
  if (hoveredNodeId.value || hoveredArcKey.value) {
    hoveredNodeId.value = null
    hoveredArcKey.value = null
    updateArcFocusAttributes()
  }
}

function onWheel(e: WheelEvent) {
  pauseIdleRotation()
  const delta = Math.sign(e.deltaY) * Math.min(0.28, Math.abs(e.deltaY) * 0.0014)
  targetDist = Math.max(MIN_DIST, Math.min(MAX_DIST, targetDist + delta))
}

function zoomBy(delta: number) {
  pauseIdleRotation()
  targetDist = Math.max(MIN_DIST, Math.min(MAX_DIST, targetDist + delta))
}

function resetView() {
  const focus = placedCenter.value ?? placedNodes.value[0]
  targetLon = focus ? focus.lon : 105
  targetLat = focus ? Math.max(-45, Math.min(45, focus.lat)) : 24
  targetDist = defaultDist
  velLon = 0
  velLat = 0
}

function clearSelection() {
  selectedNodeId.value = null
  selectedArcKey.value = null
  updateArcFocusAttributes()
  rebuildNodesAndCentre()
}

function focusNodeById(nodeId: string) {
  pauseIdleRotation()
  selectedArcKey.value = null
  selectedNodeId.value = nodeId
  const n = placedNodes.value.find((x) => x.id === nodeId)
  if (n) {
    targetLon = n.lon
    targetLat = Math.max(-72, Math.min(72, n.lat))
    if (targetDist > 2.2) targetDist = 2.05
  }
  updateArcFocusAttributes()
  rebuildNodesAndCentre()
}

function focusArcByKey(arcKey: string) {
  pauseIdleRotation()
  selectedNodeId.value = null
  selectedArcKey.value = arcKey
  updateArcFocusAttributes()
  rebuildNodesAndCentre()
}

function onKeyDown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    if (selectedNodeId.value || selectedArcKey.value) {
      e.preventDefault()
      clearSelection()
    }
    return
  }
  if (e.key === 'ArrowLeft') {
    pauseIdleRotation()
    targetLon -= 12
  } else if (e.key === 'ArrowRight') {
    pauseIdleRotation()
    targetLon += 12
  } else if (e.key === 'ArrowUp') {
    pauseIdleRotation()
    targetLat = Math.min(78, targetLat + 10)
  } else if (e.key === 'ArrowDown') {
    pauseIdleRotation()
    targetLat = Math.max(-78, targetLat - 10)
  } else if (e.key === '+' || e.key === '=') {
    zoomBy(-0.35)
  } else if (e.key === '-') {
    zoomBy(0.35)
  }
}

// ── Main Render Loop ──────────────────────────────────────────────────────────
let lastFrameTs = 0
function animate(ts: number) {
  if (disposed || !renderer || !scene || !camera) return
  rafId = requestAnimationFrame(animate)

  const dt = lastFrameTs ? Math.min(0.05, (ts - lastFrameTs) * 0.001) : 0.016
  lastFrameTs = ts

  if (autoRotate.value && !reducedMotion.value && activePointers.size === 0) {
    targetLon += dt * 5.2
  } else if (activePointers.size === 0) {
    targetLon += velLon
    targetLat = Math.max(-78, Math.min(78, targetLat + velLat))
    velLon *= 0.9
    velLat *= 0.9
    if (Math.abs(velLon) < 0.002) velLon = 0
    if (Math.abs(velLat) < 0.002) velLat = 0
  }

  const damp = reducedMotion.value ? 1 : 0.14
  currentLon += (targetLon - currentLon) * damp
  currentLat += (targetLat - currentLat) * damp
  currentDist += (targetDist - currentDist) * damp

  const nextMarkerScale = markerScaleFor(currentDist)
  if (Math.abs(nextMarkerScale - markerScale) > markerScale * 0.01) applyMarkerScale(nextMarkerScale)

  // Update zoom-aware cluster spread when crossing 10% zoom steps
  const nextBucket = Math.round(distToZoomLevel(currentDist) * 10) / 10
  if (nextBucket !== zoomSpreadBucket.value) {
    zoomSpreadBucket.value = nextBucket
  }

  syncCameraPosition()

  if (arcMaterial) {
    arcMaterial.uniforms.uTime!.value = ts * 0.001
    arcMaterial.uniforms.uMotion!.value = reducedMotion.value ? 0 : 1
    arcMaterial.uniforms.uIsDark!.value = isDark.value ? 1 : 0
  }

  renderer.render(scene, camera)
  updateProjectedLabels(ts)
}

function handleResize() {
  if (!stageEl.value || !renderer || !camera) return
  const w = Math.max(200, stageEl.value.clientWidth || 640)
  stageWidth.value = w
  const h = stageHeight.value
  defaultDist = computeDefaultDist(w, h)
  camera.aspect = w / h
  camera.updateProjectionMatrix()
  renderer.setSize(w, h, false)
}

watch([placedNodes, placedCenter, effectiveArcs], () => {
  rebuildNodesAndCentre()
  rebuildArcs()
})

watch(isDark, () => {
  applyEarthAppearance()
  rebuildNodesAndCentre()
  rebuildArcs()
})

watch(stageHeight, () => handleResize())

function onWindowKeyDown(e: KeyboardEvent) {
  if (e.key === 'Escape' && (selectedNodeId.value || selectedArcKey.value)) {
    clearSelection()
  }
}

onMounted(() => {
  if (!initScene()) return
  rebuildNodesAndCentre()
  rebuildArcs()
  syncCameraPosition()

  if (typeof ResizeObserver !== 'undefined' && stageEl.value) {
    resizeObs = new ResizeObserver(() => handleResize())
    resizeObs.observe(stageEl.value)
  }
  window.addEventListener('keydown', onWindowKeyDown)
  rafId = requestAnimationFrame(animate)
})

onBeforeUnmount(() => {
  disposed = true
  cancelAnimationFrame(rafId)
  resizeObs?.disconnect()
  window.removeEventListener('keydown', onWindowKeyDown)
  disposeMesh(nodeCoreMesh)
  disposeMesh(nodeRingMesh)
  disposeMesh(arcLines)
  disposeMesh(coastLines)
  disposeMesh(borderLines)
  disposeMesh(earthMesh)
  disposeMesh(innerAtmoMesh)
  disposeMesh(outerAtmoMesh)
  if (centreGroup) {
    centreGroup.traverse((child) => {
      if ((child as Mesh).geometry) (child as Mesh).geometry.dispose()
      const mat = (child as Mesh).material
      if (Array.isArray(mat)) mat.forEach((m) => m.dispose())
      else if (mat) mat.dispose()
    })
    centreGroup.parent?.remove(centreGroup)
    centreGroup = null
  }
  earthTexture?.dispose()
  renderer?.dispose()
  renderer = null
})

defineExpose({
  focusNodeById,
  focusArcByKey,
  clearSelection,
  resetView,
})
</script>

<style scoped>
.mh-globe-stage {
  position: relative;
  width: 100%;
  border-radius: var(--mh-radius);
  overflow: hidden;
  border: 1px solid var(--mh-hairline);
  background: radial-gradient(circle at 50% 45%, #f7fafc 0%, #e5eef2 78%, #dce7ed 100%);
  user-select: none;
  outline: none;
}
.mh-globe-stage:focus-visible {
  outline: 2px solid rgb(var(--v-theme-primary));
  outline-offset: 2px;
}
.mh-globe-stage--dark {
  background: radial-gradient(circle at 50% 45%, #13212c 0%, #0b1319 72%, #080e13 100%);
}
.mh-globe-canvas {
  display: block;
  width: 100%;
  height: 100%;
  touch-action: none;
  cursor: grab;
}
.mh-globe-canvas:active {
  cursor: grabbing;
}
.mh-globe-labels {
  position: absolute;
  inset: 0;
  pointer-events: none;
  overflow: hidden;
  z-index: 2;
}
.mh-globe-label {
  position: absolute;
  top: 0;
  left: 0;
  margin-left: 0;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 7px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 500;
  line-height: 1.3;
  white-space: nowrap;
  max-width: 152px;
  overflow: hidden;
  text-overflow: ellipsis;
  background: rgba(255, 255, 255, 0.9);
  color: #10212b;
  border: 1px solid rgba(16, 33, 43, 0.16);
  transform-origin: center;
  translate: -50% -50%;
}
.mh-globe-stage--dark .mh-globe-label {
  background: rgba(14, 22, 29, 0.84);
  color: #e6eef2;
  border-color: rgba(60, 199, 185, 0.3);
}
.mh-globe-label--centre {
  font-weight: 600;
  border-color: rgba(var(--v-theme-primary), 0.55) !important;
}
.mh-globe-label--gateway {
  border-color: rgba(var(--v-theme-accent), 0.55) !important;
}
.mh-globe-label--active {
  font-weight: 600;
  border-color: rgb(var(--v-theme-primary)) !important;
  z-index: 3;
}
.mh-globe-label__dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex: 0 0 auto;
}
.mh-globe-tip {
  position: absolute;
  pointer-events: none;
  z-index: 5;
  padding: 6px 10px;
  border-radius: 8px;
  background: rgba(var(--v-theme-surface), 0.95);
  border: 1px solid var(--mh-hairline);
  box-shadow: var(--mh-overlay-shadow);
  color: rgb(var(--v-theme-on-surface));
  max-width: 240px;
}
.mh-globe-tip__title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.78rem;
  font-weight: 600;
}
.mh-globe-tip__sub {
  font-size: 0.72rem;
  color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity));
  margin-top: 2px;
}
.mh-globe-hud {
  position: absolute;
  top: 12px;
  left: 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 3px;
  border-radius: 9px;
  background: rgba(var(--v-theme-surface), 0.86);
  backdrop-filter: blur(8px);
  border: 1px solid var(--mh-hairline);
  z-index: 4;
}
.mh-globe-attrib {
  position: absolute;
  left: 12px;
  bottom: 8px;
  font-size: 10.5px;
  line-height: 1.2;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(var(--v-theme-surface), 0.72);
  color: rgba(var(--v-theme-on-surface), 0.62);
  pointer-events: none;
  z-index: 3;
}
</style>
