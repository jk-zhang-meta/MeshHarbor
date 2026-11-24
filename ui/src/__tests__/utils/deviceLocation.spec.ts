// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, expect, it } from 'vitest'
import { dedupeLocationParts, formatDeviceLocation, formatDeviceZone } from '@/utils/deviceLocation'

describe('deviceLocation formatting & deduplication', () => {
  it('formats full Country · Province · City hierarchies cleanly', () => {
    const sz = formatDeviceLocation({
      public_ip: '203.0.113.45',
      country_code: 'cn',
      country: '中国',
      region: '广东省',
      city: '深圳市',
    })
    expect(sz).toEqual({
      locationText: '中国 · 广东省 · 深圳市',
      countryCode: 'CN',
      publicIp: '203.0.113.45',
      physicalIp: '',
      physicalSeenAt: '',
      defaultRouteVpn: false,
      hasAny: true,
    })

    const houston = formatDeviceLocation({
      public_ip: '198.51.100.22',
      country_code: 'US',
      country: '美国',
      region: '得克萨斯州',
      city: '休斯敦',
    })
    expect(houston.locationText).toBe('美国 · 得克萨斯州 · 休斯敦')
    expect(houston.countryCode).toBe('US')
  })

  it('deduplicates city-states, SARs, and direct-administered municipalities without collapsing distinct province/city pairs', () => {
    expect(dedupeLocationParts(['新加坡', '新加坡', '新加坡']).join(' · ')).toBe('新加坡')
    expect(dedupeLocationParts(['新加坡', null, '新加坡']).join(' · ')).toBe('新加坡')
    expect(dedupeLocationParts(['中国香港', '香港', '香港']).join(' · ')).toBe('中国香港')
    expect(dedupeLocationParts(['中国香港', '香港特别行政区', '香港']).join(' · ')).toBe('中国香港')
    expect(dedupeLocationParts(['Hong Kong SAR', 'Hong Kong', 'Hong Kong']).join(' · ')).toBe(
      'Hong Kong SAR',
    )
    expect(dedupeLocationParts(['中国', '北京', '北京市']).join(' · ')).toBe('中国 · 北京市')
    expect(dedupeLocationParts(['中国', '北京市', '北京市']).join(' · ')).toBe('中国 · 北京市')
    // Jilin Province + Jilin City are distinct administrative levels and must stay separate
    expect(dedupeLocationParts(['中国', '吉林省', '吉林市']).join(' · ')).toBe(
      '中国 · 吉林省 · 吉林市',
    )
  })

  it('falls back gracefully when fields are null/missing or supplied by the fallback agent record', () => {
    expect(formatDeviceLocation(null, null)).toEqual({
      locationText: '',
      countryCode: '',
      publicIp: '',
      physicalIp: '',
      physicalSeenAt: '',
      defaultRouteVpn: false,
      hasAny: false,
    })

    const merged = formatDeviceLocation(
      { public_ip: null, country: null },
      { public_ip: '203.0.113.9', country_code: 'JP', country: '日本', city: '东京' },
    )
    expect(merged).toEqual({
      locationText: '日本 · 东京',
      countryCode: 'JP',
      publicIp: '203.0.113.9',
      physicalIp: '',
      physicalSeenAt: '',
      defaultRouteVpn: false,
      hasAny: true,
    })
  })

  it('formats auto vs pinned logical network zone badges consistently', () => {
    expect(formatDeviceZone(null, null)).toEqual({
      zoneId: '',
      zoneLabel: '',
      badgeText: '',
      pinned: false,
      hasZone: false,
      zoneSource: '',
    })

    expect(
      formatDeviceZone({
        pinned_zone_id: null,
        effective_zone_id: 'cn',
        effective_zone_name: 'CN 区',
      }),
    ).toEqual({
      zoneId: 'cn',
      zoneLabel: 'CN 区',
      badgeText: 'CN 区',
      pinned: false,
      hasZone: true,
      zoneSource: '',
    })

    expect(
      formatDeviceZone({
        pinned_zone_id: 'cn',
        effective_zone_id: 'cn',
        effective_zone_name: 'CN 区',
      }),
    ).toEqual({
      zoneId: 'cn',
      zoneLabel: 'CN 区',
      badgeText: 'CN 区',
      pinned: true,
      hasZone: true,
      zoneSource: '',
    })

    expect(
      formatDeviceZone(
        { pinned_zone_id: 'siat', effective_zone_id: null, effective_zone_name: null },
        null,
        'SIAT 区',
      ),
    ).toEqual({
      zoneId: 'siat',
      zoneLabel: 'SIAT 区',
      badgeText: 'SIAT 区',
      pinned: true,
      hasZone: true,
      zoneSource: '',
    })
  })

  it('preserves FR-138 physical egress, VPN route flag, and zone_source fields', () => {
    const vpnLoc = formatDeviceLocation({
      public_ip: '198.51.100.77',
      physical_public_ip: '203.0.113.45',
      physical_seen_at: '2026-11-24T12:00:00Z',
      default_route_vpn: true,
      country_code: 'CN',
      country: '中国',
      region: '广东省',
      city: '深圳市',
    })
    expect(vpnLoc).toEqual({
      locationText: '中国 · 广东省 · 深圳市',
      countryCode: 'CN',
      publicIp: '198.51.100.77',
      physicalIp: '203.0.113.45',
      physicalSeenAt: '2026-11-24T12:00:00Z',
      defaultRouteVpn: true,
      hasAny: true,
    })

    const physOnly = formatDeviceLocation({
      physical_public_ip: '192.0.2.15',
    })
    expect(physOnly.physicalIp).toBe('192.0.2.15')
    expect(physOnly.hasAny).toBe(true)

    expect(
      formatDeviceZone({
        pinned_zone_id: null,
        effective_zone_id: 'cn',
        effective_zone_name: 'CN 区',
        zone_source: 'auto_vpn_held',
      }),
    ).toEqual({
      zoneId: 'cn',
      zoneLabel: 'CN 区',
      badgeText: 'CN 区',
      pinned: false,
      hasZone: true,
      zoneSource: 'auto_vpn_held',
    })

    expect(
      formatDeviceZone(
        { zone_source: null },
        {
          effective_zone_id: 'cn',
          effective_zone_name: 'CN 区',
          zone_source: 'auto_physical',
        },
      ),
    ).toEqual({
      zoneId: 'cn',
      zoneLabel: 'CN 区',
      badgeText: 'CN 区',
      pinned: false,
      hasZone: true,
      zoneSource: 'auto_physical',
    })
  })
})
