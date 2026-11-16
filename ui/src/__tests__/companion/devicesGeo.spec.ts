// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import {
  formatDeviceLocation as webFormatDeviceLocation,
  formatDeviceZone as webFormatDeviceZone,
} from '@/utils/deviceLocation'

const HERE = dirname(fileURLToPath(import.meta.url))
const DESKTOP_FRONT = join(HERE, '..', '..', '..', '..', 'agents', 'meshharbor-desktop', 'src', 'front')
const DESKTOP_HTML = readFileSync(join(DESKTOP_FRONT, 'index.html'), 'utf8')
const DESKTOP_GRID_JS = readFileSync(join(DESKTOP_FRONT, 'grid.js'), 'utf8')
const DESKTOP_DEVICES_JS = readFileSync(join(DESKTOP_FRONT, 'devices.js'), 'utf8')

describe('Desktop companion Devices view — Public IP, Location & Logical Zone Badge', () => {
  it('renders Public IP & Location column and Auto vs Pinned logical zone badges identically to Web UI', async () => {
    const parsed = new DOMParser().parseFromString(DESKTOP_HTML, 'text/html')
    const section = document.importNode(parsed.getElementById('view-devices')!, true)
    section.hidden = false
    document.body.innerHTML = ''
    document.body.appendChild(section)

    const items = [
      {
        id: '66f000000000000000000045',
        overlay_node_id: 'node-siat45',
        name: 'siat45',
        kind: 'agent',
        is_self: false,
        presence: 'online',
        os: 'linux',
        version: '0.4.166',
        overlay_ip: '100.64.0.45',
        public_ip: '218.17.152.45',
        country_code: 'CN',
        country: '中国',
        region: '广东省',
        city: '深圳市',
        pinned_zone_id: 'cn',
        effective_zone_id: 'cn',
        effective_zone_name: 'CN 区',
      },
      {
        id: '66f000000000000000000088',
        overlay_node_id: 'node-sg-01',
        name: 'sg-edge',
        kind: 'agent',
        is_self: false,
        presence: 'online',
        os: 'linux',
        version: '0.4.166',
        overlay_ip: '100.64.0.88',
        public_ip: '13.212.40.10',
        country_code: 'SG',
        country: '新加坡',
        region: '新加坡',
        city: '新加坡',
        pinned_zone_id: null,
        effective_zone_id: 'non-cn',
        effective_zone_name: '非 CN 区',
      },
      {
        id: '66f000000000000000000089',
        overlay_node_id: 'node-hk-01',
        name: 'hk-relay',
        kind: 'agent',
        is_self: false,
        presence: 'online',
        os: 'linux',
        version: '0.4.166',
        overlay_ip: '100.64.0.89',
        public_ip: '43.154.12.9',
        country_code: 'HK',
        country: '中国香港',
        region: '香港',
        city: '香港',
        pinned_zone_id: null,
        effective_zone_id: 'non-cn',
        effective_zone_name: '非 CN 区',
      },
      {
        id: '66f000000000000000000090',
        overlay_node_id: 'node-offline',
        name: 'offline-box',
        kind: 'agent',
        is_self: false,
        presence: 'offline',
        os: 'windows',
        version: '0.4.165',
        public_ip: null,
        country_code: null,
        country: null,
        region: null,
        city: null,
        pinned_zone_id: null,
        effective_zone_id: null,
        effective_zone_name: null,
      },
    ]

    const invokeSpy = vi.fn(async (cmd: string) => {
      if (cmd === 'cmd_devices') {
        return {
          items,
          total: items.length,
          page: 1,
          per_page: 25,
          total_pages: 1,
        }
      }
      return { ok: true }
    })

    const w = window as unknown as Record<string, unknown>
    w.MeshHarbor = {
      $: (id: string) => document.getElementById(id),
      invoke: invokeSpy,
      show: (el: HTMLElement | null) => el && (el.hidden = false),
      hide: (el: HTMLElement | null) => el && (el.hidden = true),
      fmtRelative: () => 'just now',
      on: () => undefined,
      get: () => ({
        available: true,
        status: { connected: true, orgs: [{ label: 'primary', primary: true, enabled: true }] },
        peers: [],
      }),
      currentView: () => 'devices',
      Mesh: {
        create: () => ({ render: () => undefined }),
      },
    }

    window.eval(DESKTOP_GRID_JS)
    window.eval(DESKTOP_DEVICES_JS)
    document.dispatchEvent(new Event('DOMContentLoaded'))
    document.dispatchEvent(new CustomEvent('meshharbor:view', { detail: 'devices' }))
    await new Promise((r) => setTimeout(r, 25))

    // Verify exact parity between Web TypeScript formatters and Desktop JS formatters
    const desktopApi = w.MeshHarborDevices as {
      formatDeviceLocation: (row: unknown) => ReturnType<typeof webFormatDeviceLocation>
      formatDeviceZone: (row: unknown) => ReturnType<typeof webFormatDeviceZone>
    }
    for (const row of items) {
      expect(desktopApi.formatDeviceLocation(row)).toEqual(webFormatDeviceLocation(row))
      expect(desktopApi.formatDeviceZone(row)).toEqual(webFormatDeviceZone(row))
    }

    // Verify default-visible column header
    const headers = [...document.querySelectorAll('#dv-grid thead th')].map((th) =>
      th.textContent?.trim(),
    )
    expect(headers).toContain('Public IP & Location')

    const rows = [...document.querySelectorAll('#dv-grid tbody tr')]
    expect(rows).toHaveLength(4)

    // Row 0: siat45 -> CN, 中国 · 广东省 · 深圳市, 218.17.152.45 + Pinned CN 区 badge with SVG pin icon
    const r0Loc = rows[0]!.querySelector('td[data-col="location"]') as HTMLElement
    expect(r0Loc.querySelector('.geo-code-pill')?.textContent).toBe('CN')
    expect(r0Loc.querySelector('.dv-loc-text')?.textContent).toBe('中国 · 广东省 · 深圳市')
    expect(r0Loc.querySelector('.dv-loc-ip-val')?.textContent).toBe('218.17.152.45')
    const r0Zone = rows[0]!.querySelector('.dv-chip-zone') as HTMLElement
    expect(r0Zone?.textContent).toBe('CN 区')
    expect(r0Zone?.classList.contains('is-pinned')).toBe(true)
    expect(r0Zone?.querySelector('svg.dv-pin-icon')).not.toBeNull()

    // Row 1: sg-edge -> SG, deduplicated 新加坡 + Auto 非 CN 区 badge
    const r1Loc = rows[1]!.querySelector('td[data-col="location"]') as HTMLElement
    expect(r1Loc.querySelector('.geo-code-pill')?.textContent).toBe('SG')
    expect(r1Loc.querySelector('.dv-loc-text')?.textContent).toBe('新加坡')
    expect(r1Loc.querySelector('.dv-loc-ip-val')?.textContent).toBe('13.212.40.10')
    const r1Zone = rows[1]!.querySelector('.dv-chip-zone') as HTMLElement
    expect(r1Zone?.textContent).toBe('非 CN 区')
    expect(r1Zone?.classList.contains('is-pinned')).toBe(false)

    // Row 2: hk-relay -> HK, deduplicated 中国香港 + Auto 非 CN 区 badge
    const r2Loc = rows[2]!.querySelector('td[data-col="location"]') as HTMLElement
    expect(r2Loc.querySelector('.geo-code-pill')?.textContent).toBe('HK')
    expect(r2Loc.querySelector('.dv-loc-text')?.textContent).toBe('中国香港')
    expect(rows[2]!.querySelector('.dv-chip-zone')?.textContent).toBe('非 CN 区')

    // Row 3: offline-box -> graceful fallback '—' and no zone chip when unzoned
    const r3Loc = rows[3]!.querySelector('td[data-col="location"]') as HTMLElement
    expect((r3Loc.querySelector('.dv-loc-cell') as HTMLElement).hidden).toBe(true)
    expect(r3Loc.textContent?.trim()).toBe('—')
    expect(rows[3]!.querySelector('.dv-chip-zone')).toBeNull()
  })
})
