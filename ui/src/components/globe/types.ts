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
  /** Optional explicit coordinates (e.g. centre override or future precision). */
  lat?: number | null
  lon?: number | null
  /** Machine facts — omitted in the detail panel whenever absent. */
  os?: string | null
  version?: string | null
  lastSeenAt?: string | null
  overlayIp?: string | null
  /** Populated ONLY where the current UI already displays public IP (fleet view). */
  publicIp?: string | null
  /** Logical network zone (T6) or business zone (T7). */
  zoneId?: string | null
  zoneName?: string | null
  zonePinned?: boolean
  zoneKind?: 'mainland' | 'non_mainland' | 'centre' | string | null
  /** FR-134 optional path to the centre. */
  managementPath?: GlobeManagementPath | null
  /** Optional custom colour override (e.g. T7 zone dot palette). */
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
  /** T7 backbone link state. */
  enabled?: boolean
  kind?: 'peer' | 'control' | 'backbone'
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
