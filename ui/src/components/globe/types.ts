// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Shared data contracts for the lazy-loaded 3D WebGL2 MeshGlobe module.
// Designed to power both the dashboard overlay mesh (T6: MeshGraph.vue) and
// the zone/server backbone editor (T7: ServerTopologySection.vue).
import type { MeshEdgeEnd } from '@/utils/mesh'

export type GlobeNodeRole = 'device' | 'gateway' | 'entry' | 'centre' | 'server'
export type GlobePresence = 'online' | 'stale' | 'offline'

/** FR-134 readiness: optional management path from a device to the centre. */
export interface GlobeManagementPath {
  mode: 'direct' | 'gateway' | 'last_resort_direct' | string
  gatewayName?: string | null
  entries?: string[]
}

/** FR-137 — live gateway management entry state & connected device count. */
export interface GlobeManagementEntry {
  listening: boolean
  port?: number | null
  deviceCount: number
}

export interface GlobeNode {
  /** Primary identifier (overlay node id in T6; agent_id in T7). */
  id: string
  /** Optional backing agent id (when different from overlay node id). */
  agentId?: string | null
  name: string
  online: boolean
  presence?: GlobePresence
  role?: GlobeNodeRole
  isGateway?: boolean
  isEntry?: boolean
  isCentre?: boolean
  /** Location fields — populated ONLY from data the server already returns. */
  countryCode?: string | null
  country?: string | null
  region?: string | null
  city?: string | null
  relayHome?: string | null
  /** Optional explicit coordinates (e.g. centre override or P6 precision). */
  lat?: number | null
  lon?: number | null
  /** P6 optional 67%-confidence accuracy radius in km (rendered as 64-gon circle at z>=3). */
  accuracyRadiusKm?: number | null
  /** P6 optional explicit precision tier (`coords` | `city` | `region` | `country` | `unknown`). */
  geoLevel?: 'coords' | 'city' | 'region' | 'country' | 'unknown' | null
  /** Machine facts — omitted in the detail panel whenever absent. */
  os?: string | null
  version?: string | null
  lastSeenAt?: string | null
  overlayIp?: string | null
  /** Populated ONLY where the current UI already displays public IP (fleet view). */
  publicIp?: string | null
  /** Logical network zone (T6) or backbone zone (T7/S12). */
  zoneId?: string | null
  zoneName?: string | null
  /** FR-137 — all zone ids & display names when a gateway serves >=1 zone. */
  zoneIds?: string[]
  zoneNames?: string[]
  /** S12 — resolved device count in the node's primary zone for the gateway zone chip. */
  zoneDeviceCount?: number | null
  zonePinned?: boolean
  zoneKind?: 'mainland' | 'non_mainland' | 'centre' | string | null
  /** FR-134 optional path to the centre. */
  managementPath?: GlobeManagementPath | null
  /** FR-137 optional live gateway management entry state. */
  managementEntry?: GlobeManagementEntry | null
  /** Optional custom colour override (e.g. S12/T7 zone palette). */
  color?: string
  /** T7 interaction hook: highlights node while picking the second link endpoint. */
  pending?: boolean
}

export interface GlobeArc {
  key: string
  from: string
  to: string
  carrier: string
  /** Primary arc colour (hex/rgb CSS string). */
  color: string
  /** Asymmetric per-direction colours when both ends disagree. */
  fromColor?: string
  toColor?: string
  asymmetric?: boolean
  stalled?: boolean
  blocked?: boolean
  dashed?: boolean
  rttMs?: number | null
  reports?: number
  ends?: MeshEdgeEnd[]
  /** FR-137 — true when a gateway↔gateway link spans distinct zones. */
  crossZone?: boolean
  /** S12 — true when the backbone link is unidirectional (draws directional arrows every 120 px). */
  directional?: boolean
  /** T7 backbone link state (false renders muted 1.5 px dashed [2,2]). */
  enabled?: boolean
  kind?: 'peer' | 'control' | 'backbone' | 'mgmt_path'
}

export interface GlobeCenter {
  id: string
  name: string
  lat?: number | null
  lon?: number | null
  countryCode?: string | null
  locationLabel?: string | null
}

export type GeoPrecision = 'coords' | 'city' | 'region' | 'country' | 'relay_home' | 'unknown'

export interface ResolvedGeo {
  lon: number
  lat: number
  precision: GeoPrecision
  /** Human-readable location string (never fabricated; empty when unknown). */
  locationLabel: string
  /** Cluster anchor key so co-located nodes spread deterministically together. */
  bucketKey: string
}

export interface PlacedGlobeNode extends GlobeNode {
  /** Base resolved anchor coordinates before cluster spread. */
  baseLon: number
  baseLat: number
  /** Effective coordinates after zoom-aware deterministic cluster spread. */
  lon: number
  lat: number
  precision: GeoPrecision
  locationLabel: string
  clusterSize: number
  clusterIndex: number
}

export interface PlacedGlobeCenter extends GlobeCenter {
  lon: number
  lat: number
  /** True when elevated as an orbital control-plane hub (no server-provided geo). */
  orbital: boolean
}

export interface ArcVisualState {
  key: string
  opacity: number
  emphasis: number // 0 = dimmed, 0.5 = baseline, 1.0 = highlighted
  pulseStrength: number
  dashed: boolean
}
