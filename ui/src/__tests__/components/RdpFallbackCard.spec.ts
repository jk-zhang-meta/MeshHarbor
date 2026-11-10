// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import RdpFallbackCard from '@/components/remote/RdpFallbackCard.vue'
import {
  RC_ERROR_CODE_TABLE,
  RDP_SCREEN_LOCK_WARNING,
  formatMhRdpCommand,
  getDeviceAutoRdpFallback,
  hasDesktopRdpBridge,
  setDeviceAutoRdpFallback,
  shouldShowRdpFallbackCard,
} from '@/utils/rdpFallback'

const HERE = dirname(fileURLToPath(import.meta.url))
const DESKTOP_FRONT = join(
  HERE,
  '..',
  '..',
  '..',
  '..',
  'agents',
  'meshharbor-desktop',
  'src',
  'front',
)
const DESKTOP_HTML = readFileSync(join(DESKTOP_FRONT, 'index.html'), 'utf8')
const DESKTOP_GRID_JS = readFileSync(join(DESKTOP_FRONT, 'grid.js'), 'utf8')
const DESKTOP_DEVICES_JS = readFileSync(join(DESKTOP_FRONT, 'devices.js'), 'utf8')

const DEVICE_ID = '66366f7a7230306d6c657232'
const DEVICE_NAME = 'surface-pro'

describe('RC/RDP Phase C — RdpFallbackCard & rdpFallback rules', () => {
  beforeEach(() => {
    window.localStorage.clear()
    delete (window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__
    delete (window as unknown as Record<string, unknown>).__TAURI__
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__
  })

  afterEach(() => {
    window.localStorage.clear()
    delete (window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__
    delete (window as unknown as Record<string, unknown>).__TAURI__
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__
  })

  describe('1. Exhaustive RC error code table visibility (`RC_ERROR_CODE_TABLE`)', () => {
    it.each(RC_ERROR_CODE_TABLE)(
      'code=$code (source=$source) -> showRdpCard=$showRdpCard when rdp_available=true',
      (entry) => {
        const isMediaUnavailable = entry.source === 'rc:media-unavailable'
        const decision = shouldShowRdpFallbackCard({
          phase: isMediaUnavailable ? 'connected' : 'error',
          errorCode: isMediaUnavailable ? null : entry.code,
          mediaUnavailableReason: isMediaUnavailable ? entry.code : null,
          rdpAvailable: true,
        })
        expect(decision).toBe(entry.showRdpCard)

        const wrapper = mount(RdpFallbackCard, {
          props: {
            phase: isMediaUnavailable ? 'connected' : 'error',
            errorCode: isMediaUnavailable ? null : entry.code,
            errorMessage: `RC failure: ${entry.code}`,
            mediaUnavailableReason: isMediaUnavailable ? entry.code : null,
            mediaUnavailableHint: isMediaUnavailable ? `Media unavailable: ${entry.code}` : null,
            rdpAvailable: true,
            rdpPort: 3389,
            deviceId: DEVICE_ID,
            deviceName: DEVICE_NAME,
          },
        })

        const card = wrapper.find('[data-test="rdp-fallback-card"]')
        expect(card.exists()).toBe(entry.showRdpCard)
        if (entry.showRdpCard) {
          expect(wrapper.find('[data-test="rdp-screen-lock-warning"]').text()).toContain(
            RDP_SCREEN_LOCK_WARNING,
          )
          expect(wrapper.find('[data-test="rdp-fallback-retry-btn"]').exists()).toBe(true)
        }
      },
    )
  })

  describe('2. Hidden when `rdp_available=false` (including Windows Home) or absent', () => {
    it.each(RC_ERROR_CODE_TABLE.filter((e) => e.showRdpCard))(
      'hides card for eligible code=$code when rdp_available=false',
      (entry) => {
        const isMediaUnavailable = entry.source === 'rc:media-unavailable'
        expect(
          shouldShowRdpFallbackCard({
            phase: isMediaUnavailable ? 'connected' : 'error',
            errorCode: isMediaUnavailable ? null : entry.code,
            mediaUnavailableReason: isMediaUnavailable ? entry.code : null,
            rdpAvailable: false,
          }),
        ).toBe(false)

        const wrapper = mount(RdpFallbackCard, {
          props: {
            phase: isMediaUnavailable ? 'connected' : 'error',
            errorCode: isMediaUnavailable ? null : entry.code,
            mediaUnavailableReason: isMediaUnavailable ? entry.code : null,
            rdpAvailable: false,
            deviceId: DEVICE_ID,
            deviceName: DEVICE_NAME,
          },
        })
        expect(wrapper.find('[data-test="rdp-fallback-card"]').exists()).toBe(false)
      },
    )
  })

  describe('3. Never auto-switches without per-device confirmation in viewer localStorage', () => {
    it('does not auto-invoke cmd_open_rdp when per-device toggle is off (default)', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = {
        openRdp: openRdpSpy,
      }

      expect(getDeviceAutoRdpFallback(DEVICE_ID)).toBe(false)

      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'connected',
          mediaUnavailableReason: 'no_display',
          mediaUnavailableHint: 'No physical display attached',
          rdpAvailable: true,
          rdpPort: 3389,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })
      await nextTick()

      // Must NOT auto-switch when toggle is off
      expect(openRdpSpy).not.toHaveBeenCalled()

      // Enabling the per-device toggle requires confirming the screen-lock warning first
      const toggle = wrapper.find('[data-test="rdp-auto-toggle"]')
      ;(toggle.element as HTMLInputElement).checked = true
      await toggle.trigger('change')

      // Still false until confirmed
      expect(getDeviceAutoRdpFallback(DEVICE_ID)).toBe(false)
      const prompt = wrapper.find('[data-test="rdp-auto-confirm-prompt"]')
      expect(prompt.exists()).toBe(true)
      expect(prompt.text()).toContain(RDP_SCREEN_LOCK_WARNING)

      // Cancel keeps it off
      await wrapper.find('[data-test="rdp-auto-confirm-cancel"]').trigger('click')
      expect(getDeviceAutoRdpFallback(DEVICE_ID)).toBe(false)
      expect(wrapper.find('[data-test="rdp-auto-confirm-prompt"]').exists()).toBe(false)

      // Try again and accept confirmation -> saved for THIS device only
      ;(toggle.element as HTMLInputElement).checked = true
      await toggle.trigger('change')
      await wrapper.find('[data-test="rdp-auto-confirm-accept"]').trigger('click')
      expect(getDeviceAutoRdpFallback(DEVICE_ID)).toBe(true)
      expect(getDeviceAutoRdpFallback('66366f7a7230306d6c657299')).toBe(false)

      // Direct helper call without confirmation is also rejected
      expect(setDeviceAutoRdpFallback('66366f7a7230306d6c657299', true, false)).toBe(false)
    })

    it('invokes cmd_open_rdp when user explicitly clicks "用 RDP 连接" with desktop bridge', async () => {
      const invokeSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__TAURI__ = {
        core: { invoke: invokeSpy },
      }
      expect(hasDesktopRdpBridge()).toBe(true)

      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'connection_timed_out',
          errorMessage: 'connection timed out',
          rdpAvailable: true,
          rdpPort: 3389,
          rdpCertSha256:
            'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99',
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
          org: 'acme',
        },
      })

      expect(wrapper.find('[data-test="rdp-fallback-no-bridge"]').exists()).toBe(false)
      const connectBtn = wrapper.find('[data-test="rdp-fallback-connect-btn"]')
      expect(connectBtn.exists()).toBe(true)
      expect(connectBtn.text()).toBe('用 RDP 连接')

      await connectBtn.trigger('click')
      expect(invokeSpy).toHaveBeenCalledTimes(1)
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_rdp', {
        target: DEVICE_ID,
        org: 'acme',
        port: 3389,
        certSha256:
          'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99',
      })
    })
  })

  describe('4. Shows "在桌面应用中打开" and `mh rdp <设备名>` copy button when bridge is absent', () => {
    it('renders CLI copy fallback and hides direct connect button in system browser', async () => {
      expect(hasDesktopRdpBridge()).toBe(false)
      const writeTextSpy = vi.fn(async () => undefined)
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: writeTextSpy },
      })

      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'connected',
          mediaUnavailableReason: 'no_display',
          mediaUnavailableHint: 'The host has no physical display attached.',
          rdpAvailable: true,
          rdpPort: 3389,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })

      expect(wrapper.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(false)
      const noBridgeBox = wrapper.find('[data-test="rdp-fallback-no-bridge"]')
      expect(noBridgeBox.exists()).toBe(true)
      expect(noBridgeBox.text()).toContain('在桌面应用中打开')

      const cliCmd = wrapper.find('[data-test="rdp-fallback-cli-cmd"]')
      expect(cliCmd.text()).toBe('mh rdp surface-pro')
      expect(formatMhRdpCommand('My Surface Pro')).toBe('mh rdp "My Surface Pro"')

      const copyBtn = wrapper.find('[data-test="rdp-fallback-copy-btn"]')
      await copyBtn.trigger('click')
      expect(writeTextSpy).toHaveBeenCalledWith('mh rdp surface-pro')
      expect(copyBtn.text()).toBe('已复制')
    })
  })

  describe('5. Desktop device list split button (`agents/meshharbor-desktop/src/front/devices.js`)', () => {
    it('renders primary "连接" (cmd_open_remote) and dropdown items "用 RDP 连接" & "独立会话（高级）" (cmd_open_rdp)', async () => {
      const parsed = new DOMParser().parseFromString(DESKTOP_HTML, 'text/html')
      const section = document.importNode(parsed.getElementById('view-devices')!, true)
      section.hidden = false
      document.body.innerHTML = ''
      document.body.appendChild(section)

      const invokeSpy = vi.fn(async (cmd: string) => {
        if (cmd === 'cmd_devices') {
          return {
            items: [
              {
                id: DEVICE_ID,
                overlay_node_id: 'node-surface-01',
                name: DEVICE_NAME,
                kind: 'agent',
                is_self: false,
                presence: 'online',
                os: 'windows',
              },
            ],
            total: 1,
            page: 1,
            per_page: 25,
          }
        }
        return { ok: true }
      })

      const listeners: Record<string, Array<(v: unknown) => void>> = {}
      const w = window as unknown as Record<string, unknown>
      w.MeshHarbor = {
        $: (id: string) => document.getElementById(id),
        invoke: invokeSpy,
        show: (el: HTMLElement | null) => el && (el.hidden = false),
        hide: (el: HTMLElement | null) => el && (el.hidden = true),
        fmtRelative: () => 'just now',
        on: (k: string, fn: (v: unknown) => void) => {
          ;(listeners[k] ||= []).push(fn)
        },
        get: () => ({
          available: true,
          orgs: [{ label: 'primary', primary: true }],
          peers: [],
        }),
        currentView: () => 'devices',
        Mesh: {
          create: () => ({
            render: () => undefined,
          }),
        },
      }
      window.eval(DESKTOP_GRID_JS)
      window.eval(DESKTOP_DEVICES_JS)
      document.dispatchEvent(new Event('DOMContentLoaded'))
      document.dispatchEvent(new CustomEvent('meshharbor:view', { detail: 'devices' }))
      await new Promise((r) => setTimeout(r, 20))

      const mainBtn = document.querySelector('.dv-split-main') as HTMLButtonElement | null
      const toggleBtn = document.querySelector('.dv-split-toggle') as HTMLButtonElement | null
      const menu = document.querySelector('.dv-split-menu') as HTMLElement | null
      const rdpItem = document.querySelector('.dv-split-item-rdp') as HTMLButtonElement | null
      const standaloneItem = document.querySelector(
        '.dv-split-item-standalone',
      ) as HTMLButtonElement | null

      expect(mainBtn).not.toBeNull()
      expect(mainBtn!.textContent).toBe('连接')
      expect(toggleBtn).not.toBeNull()
      expect(menu).not.toBeNull()
      expect(menu!.hidden).toBe(true)
      expect(rdpItem?.textContent).toBe('用 RDP 连接')
      expect(standaloneItem?.textContent).toBe('独立会话（高级）')

      // 1. Clicking primary "连接" invokes cmd_open_remote
      mainBtn!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_remote', {
        agentId: DEVICE_ID,
        org: null,
      })

      // 2. Clicking dropdown toggle opens menu; clicking "用 RDP 连接" invokes cmd_open_rdp
      toggleBtn!.click()
      expect(menu!.hidden).toBe(false)
      rdpItem!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(menu!.hidden).toBe(true)
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_rdp', {
        target: 'node-surface-01',
        org: null,
      })

      // 3. Clicking "独立会话（高级）" also invokes cmd_open_rdp
      invokeSpy.mockClear()
      toggleBtn!.click()
      standaloneItem!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_rdp', {
        target: 'node-surface-01',
        org: null,
      })
    })
  })
})
