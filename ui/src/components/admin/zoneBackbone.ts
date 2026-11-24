// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure deterministic zone colour palette (aligned to S2 WCAG >= 3:1 Okabe–Ito tokens)
// and Zone Backbone -> MeshGlobe data mapping for `ServerTopologySection.vue` (FR-137 + S12).
// Zero DOM dependencies so every transformation is directly unit-tested.
import type { GlobeArc, GlobeNode } from '@/components/globe/types'
import { DARK_TOKENS, LIGHT_TOKENS } from '@/components/globe-v2/tokens'
import type {
  BackboneGatewayView,
  BackboneLinkView,
  BackboneZoneView,
} from '@/stores/serverTopology'
import { edgeSides, type MeshEdgeEnd } from '@/utils/mesh'

export const CENTRE_ZONE_COLOR_LIGHT = '#0F766E'
export const CENTRE_ZONE_COLOR_DARK = '#2DD4BF'

function hashZoneId(id: string): number {
  let h = 2166136261
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

/** Deterministic colour for a zone: distinct centre teal when `is_centre`, S2 Okabe–Ito `tokens.zones` otherwise. */
export function zoneColor(
  zone: Pick<BackboneZoneView, 'id' | 'is_centre'>,
  isDark = false,
  index?: number,
): string {
  if (zone.is_centre) {
    return isDark ? CENTRE_ZONE_COLOR_DARK : CENTRE_ZONE_COLOR_LIGHT
  }
  const palette = isDark ? DARK_TOKENS.zones : LIGHT_TOKENS.zones
  const slot = index != null ? index : hashZoneId(zone.id)
  return palette[slot % palette.length]!
}

export interface BackboneCarrierColors {
  direct: string
  org_relay: string
  relay: string
  derp: string
  tunnel: string
  blocked: string
  unknown: string
}

/** Resolve the effective carrier class, elevating `relay` with `relay === 'org_relay'` to its own class. */
export function effectiveBackboneCarrier(
  carrier: string,
  ends?: readonly MeshEdgeEnd[],
): string {
  if (carrier === 'relay' && ends?.some((e) => e.carrier === 'relay' && e.relay === 'org_relay')) {
    return 'org_relay'
  }
  return carrier
}

export function backboneCarrierColor(
  carrier: string,
  palette: BackboneCarrierColors,
  relayQualifier?: string | null,
): string {
  if (carrier === 'relay' && relayQualifier === 'org_relay') return palette.org_relay
  switch (carrier) {
    case 'direct':
      return palette.direct
    case 'org_relay':
      return palette.org_relay
    case 'relay':
      return palette.relay
    case 'derp':
      return palette.derp
    case 'tunnel':
      return palette.tunnel
    case 'blocked':
      return palette.blocked
    default:
      return palette.unknown
  }
}

export interface BackboneGlobeData {
  nodes: GlobeNode[]
  arcs: GlobeArc[]
  zoneColors: Map<string, string>
}

/**
 * Map a `ZoneBackboneResponse` (optionally filtered to a single `selectedZoneId`)
 * into shared `GlobeNode[]` and `GlobeArc[]` props for `MeshGlobe.vue` (`view-mode="backbone"`).
 */
export function buildBackboneGlobeData(
  zones: readonly BackboneZoneView[],
  gateways: readonly BackboneGatewayView[],
  links: readonly BackboneLinkView[],
  options: {
    selectedZoneId?: string | null
    isDark?: boolean
    carrierColors: BackboneCarrierColors
  },
): BackboneGlobeData {
  const isDark = Boolean(options.isDark)
  const zoneById = new Map<string, BackboneZoneView>()
  const zoneColors = new Map<string, string>()

  let nonCentreIdx = 0
  for (const z of zones) {
    zoneById.set(z.id, z)
    if (z.is_centre) {
      zoneColors.set(z.id, zoneColor(z, isDark))
    } else {
      zoneColors.set(z.id, zoneColor(z, isDark, nonCentreIdx++))
    }
  }

  const filterZone = options.selectedZoneId || null
  const visibleGateways = filterZone
    ? gateways.filter((g) => g.zone_ids.includes(filterZone))
    : gateways
  const visibleIds = new Set(visibleGateways.map((g) => g.agent_id))

  const nodes: GlobeNode[] = visibleGateways.map((gw) => {
    const primaryZoneId =
      (gw.is_centre
        ? gw.zone_ids.find((zid) => zoneById.get(zid)?.is_centre)
        : undefined) ??
      (filterZone && gw.zone_ids.includes(filterZone) ? filterZone : gw.zone_ids[0]) ??
      null
    const primaryZone = primaryZoneId ? zoneById.get(primaryZoneId) : undefined
    const zoneNames = gw.zone_ids.map((zid) => zoneById.get(zid)?.name ?? zid)
    const color = primaryZone
      ? zoneColors.get(primaryZone.id)
      : gw.is_centre
        ? isDark
          ? CENTRE_ZONE_COLOR_DARK
          : CENTRE_ZONE_COLOR_LIGHT
        : undefined

    // FR-134 management path readiness summary
    const managementPath = gw.is_centre
      ? { mode: 'centre_host' }
      : gw.serving_relay && gw.entry_listening
        ? {
            mode: 'gateway_entry_ready',
            gatewayName: gw.name,
            entries: gw.entry_port ? [`:${gw.entry_port}`] : [],
          }
        : gw.serving_relay
          ? { mode: 'gateway_relay_only', gatewayName: gw.name }
          : primaryZone?.is_centre
            ? { mode: 'direct' }
            : null

    return {
      id: gw.agent_id,
      agentId: gw.agent_id,
      name: gw.name,
      online: gw.online,
      presence: gw.online ? 'online' : 'offline',
      role: gw.is_centre
        ? 'centre'
        : gw.serving_relay
          ? 'gateway'
          : gw.entry_listening
            ? 'entry'
            : 'server',
      // Keep the Centre reporting role strictly separate from Gateway/Forwarder
      // and Management Entry roles: only mark Gateway when `serving_relay` is true,
      // and Entry when `serving_relay && entry_listening` is true.
      isGateway: gw.serving_relay,
      isEntry: gw.serving_relay && gw.entry_listening,
      isCentre: gw.is_centre,
      countryCode: gw.country_code ?? null,
      country: gw.country ?? null,
      region: gw.region ?? null,
      city: gw.city ?? null,
      relayHome: gw.relay_home ?? null,
      os: gw.os || null,
      version: gw.agent_version || null,
      lastSeenAt: gw.last_seen_at || null,
      publicIp: gw.public_ip ?? null,
      zoneId: primaryZoneId,
      zoneName: primaryZone?.name ?? zoneNames[0] ?? null,
      zoneIds: [...gw.zone_ids],
      zoneNames,
      zoneDeviceCount: primaryZone?.device_count ?? null,
      zoneKind: primaryZone?.is_centre || gw.is_centre ? 'centre' : null,
      managementPath,
      managementEntry:
        gw.serving_relay || gw.entry_listening
          ? {
              listening: gw.entry_listening,
              port: gw.entry_port ?? null,
              deviceCount: gw.entry_device_count,
            }
          : null,
      color,
    }
  })

  const arcs: GlobeArc[] = []
  for (const link of links) {
    if (!visibleIds.has(link.from_agent_id) || !visibleIds.has(link.to_agent_id)) continue
    const sides = edgeSides(link.ends, link.from_agent_id, link.to_agent_id)
    const effective = effectiveBackboneCarrier(link.carrier, link.ends)
    const baseColor = backboneCarrierColor(effective, options.carrierColors)
    const fromColor = sides.from
      ? backboneCarrierColor(sides.from.carrier, options.carrierColors, sides.from.relay)
      : baseColor
    const toColor = sides.to
      ? backboneCarrierColor(sides.to.carrier, options.carrierColors, sides.to.relay)
      : baseColor
    const asymmetric = Boolean(sides.asymmetric || (sides.from && sides.to && fromColor !== toColor))
    const directional = link.reports === 1 || link.ends.length === 1

    arcs.push({
      key: `${link.from_agent_id}:${link.to_agent_id}`,
      from: link.from_agent_id,
      to: link.to_agent_id,
      carrier: effective,
      color: baseColor,
      fromColor,
      toColor,
      asymmetric,
      stalled: link.stalled,
      blocked: link.carrier === 'blocked',
      dashed: link.stalled || link.carrier === 'blocked',
      rttMs: link.rtt_ms ?? null,
      reports: link.reports,
      ends: link.ends,
      crossZone: link.cross_zone,
      directional,
      enabled: true,
      kind: 'backbone',
    })
  }

  return { nodes, arcs, zoneColors }
}
