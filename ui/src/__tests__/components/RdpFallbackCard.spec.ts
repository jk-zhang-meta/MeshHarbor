// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { flushPromises, mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import RdpFallbackCard from '@/components/remote/RdpFallbackCard.vue'
import { setLocale } from '@/plugins/i18n'
import {
  RC_ERROR_CODE_TABLE,
  rdpMeshDisabledHint,
  rdpScreenLockWarning,
  rdpUnpinnedCertNotice,
  formatMhRdpCommand,
  RDP_FALLBACK_RETRY_WINDOW_MS,
  getDeviceAutoRdpFallback,
  getLastAutoRcRetry,
  hasDesktopRdpBridge,
  invokeDesktopOpenRdp,
  nextRdpFallbackStep,
  noteAutoRcRetry,
  rdpFallbackMode,
  resetAutoRcRetries,
  setDeviceAutoRdpFallback,
  shouldShowRdpFallbackCard,
} from '@/utils/rdpFallback'

// The desktop companion (devices.js) is English. The web card speaks the
// reader's language (FR-131 P3: `remote.viewer.rdp.*`); these cases read it in
// Chinese, the language it was first written in, so its assertions hold the
// Chinese words, and the English ones are the desktop's.
const DESKTOP_RDP_SCREEN_LOCK_WARNING = 'An RDP session locks the remote computer’s local screen.'
const DESKTOP_RDP_UNPINNED_NOTICE =
  'This device reported no certificate fingerprint; the RDP client will check the certificate itself.'
const DESKTOP_RDP_MESH_HINT =
  'Turn on RDP over the mesh on the target device (rdp_over_mesh = true).'

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
    resetAutoRcRetries()
    window.localStorage.clear()
    setLocale('zh-CN')
    delete (window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__
    delete (window as unknown as Record<string, unknown>).__TAURI__
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__
  })

  afterEach(() => {
    setLocale('en')
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
            rdpScreenLockWarning(),
          )
          expect(wrapper.find('[data-test="rdp-fallback-retry-btn"]').exists()).toBe(true)
        }
      },
    )

    it('classifies agent_busy as ineligible (someone is already viewing the machine) and never shows the RDP card', () => {
      const spec = RC_ERROR_CODE_TABLE.find((e) => e.code === 'agent_busy')
      expect(spec).toBeDefined()
      expect(spec?.showRdpCard).toBe(false)
      expect(spec?.category).toBe('user-consent-or-host-stop')
      expect(
        shouldShowRdpFallbackCard({
          phase: 'error',
          errorCode: 'agent_busy',
          rdpAvailable: true,
        }),
      ).toBe(false)
    })
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

  describe('3. FR-120: switches to RDP by itself; a viewer opt-out brings the buttons back', () => {
    it('auto-invokes cmd_open_rdp by default, with no chooser, and honours a per-device opt-out', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = {
        openRdp: openRdpSpy,
      }

      expect(getDeviceAutoRdpFallback(DEVICE_ID)).toBe(true)

      const props = {
        phase: 'connected',
        mediaUnavailableReason: 'no_display',
        mediaUnavailableHint: 'No physical display attached',
        rdpAvailable: true,
        rdpMeshReachable: true,
        rdpPort: 3389,
        deviceId: DEVICE_ID,
        deviceName: DEVICE_NAME,
      }
      const wrapper = mount(RdpFallbackCard, { props })
      await flushPromises()

      expect(openRdpSpy).toHaveBeenCalledTimes(1)
      expect(wrapper.find('[data-test="rdp-auto-status"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-fallback-retry-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-auto-toggle"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-auto-confirm-prompt"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-screen-lock-warning"]').text()).toContain(
        rdpScreenLockWarning(),
      )

      // The opt-out is per device and per viewer: this device only.
      expect(setDeviceAutoRdpFallback(DEVICE_ID, false)).toBe(false)
      expect(getDeviceAutoRdpFallback('66366f7a7230306d6c657299')).toBe(true)
      openRdpSpy.mockClear()
      const optedOut = mount(RdpFallbackCard, { props })
      await flushPromises()
      expect(openRdpSpy).not.toHaveBeenCalled()
      expect(optedOut.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(true)
      expect(optedOut.find('[data-test="rdp-fallback-retry-btn"]').exists()).toBe(true)

      // Clearing the opt-out returns to the default.
      expect(setDeviceAutoRdpFallback(DEVICE_ID, true)).toBe(true)
    })

    it('invokes cmd_open_rdp when user explicitly clicks "用 RDP 连接" with desktop bridge', async () => {
      const invokeSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__TAURI__ = {
        core: { invoke: invokeSpy },
      }
      expect(hasDesktopRdpBridge()).toBe(true)
      // The manual button is what an opted-out viewer gets.
      setDeviceAutoRdpFallback(DEVICE_ID, false)

      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'connection_timed_out',
          errorMessage: 'connection timed out',
          rdpAvailable: true,
          rdpMeshReachable: true,
          rdpPort: 3389,
          rdpCertSha256:
            'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99',
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
          org: 'acme',
        },
      })

      expect(wrapper.find('[data-test="rdp-fallback-no-bridge"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-unpinned-cert-notice"]').exists()).toBe(false)
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

    it('displays unpinned certificate notice when rdpCertSha256 is absent and surfaces offline precheck error', async () => {
      const openRdpErrSpy = vi.fn(async () => {
        throw new Error('经网格无法连到目标 RDP 端口 (surface-pro:3389)：Host unreachable')
      })
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = {
        openRdp: openRdpErrSpy,
      }

      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'agent_offline',
          errorMessage: 'agent offline',
          rdpAvailable: true,
          rdpMeshReachable: true,
          rdpPort: 3389,
          rdpCertSha256: null,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })

      const notice = wrapper.find('[data-test="rdp-unpinned-cert-notice"]')
      expect(notice.exists()).toBe(true)
      expect(notice.text()).toBe(rdpUnpinnedCertNotice())

      // The automatic launch ran and failed: its error shows, and the buttons
      // come back as the recovery.
      await flushPromises()
      expect(openRdpErrSpy).toHaveBeenCalledTimes(1)
      const errEl = wrapper.find('[data-test="rdp-fallback-bridge-error"]')
      expect(errEl.exists()).toBe(true)
      expect(errEl.text()).toContain('经网格无法连到目标 RDP 端口')
      expect(wrapper.find('[data-test="rdp-auto-status"]').exists()).toBe(false)

      await wrapper.find('[data-test="rdp-fallback-connect-btn"]').trigger('click')
      await flushPromises()
      expect(openRdpErrSpy).toHaveBeenCalledTimes(2)
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
          rdpMeshReachable: true,
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
    it('renders primary "Connect" (cmd_open_remote), removes the duplicate standalone-session item, and requires in-app screen-lock confirmation before invoking cmd_open_rdp', async () => {
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
                rdp_available: true,
                rdp_mesh_reachable: true,
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
      const confirmBox = document.querySelector('.dv-rdp-confirm') as HTMLElement | null
      const confirmText = document.querySelector('.dv-rdp-confirm-text') as HTMLElement | null
      const confirmAcceptBtn = document.querySelector(
        '.dv-rdp-confirm-accept',
      ) as HTMLButtonElement | null
      const confirmCancelBtn = document.querySelector(
        '.dv-rdp-confirm-cancel',
      ) as HTMLButtonElement | null

      expect(mainBtn).not.toBeNull()
      expect(mainBtn!.textContent).toBe('Connect')
      expect(toggleBtn).not.toBeNull()
      expect(menu).not.toBeNull()
      expect(menu!.hidden).toBe(true)
      expect(rdpItem?.textContent).toBe('Connect with RDP')
      expect(standaloneItem).toBeNull()
      expect(confirmBox).not.toBeNull()
      expect(confirmBox!.hidden).toBe(true)
      expect(confirmText?.textContent).toBe(DESKTOP_RDP_SCREEN_LOCK_WARNING)

      // 1. Clicking primary "Connect" invokes cmd_open_remote
      mainBtn!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_remote', {
        agentId: DEVICE_ID,
        org: null,
      })

      // 2. Clicking dropdown toggle opens menu; clicking "Connect with RDP" shows in-app confirmation without calling cmd_open_rdp yet
      invokeSpy.mockClear()
      toggleBtn!.click()
      expect(menu!.hidden).toBe(false)
      expect(rdpItem!.hidden).toBe(false)
      expect(confirmBox!.hidden).toBe(true)

      rdpItem!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(menu!.hidden).toBe(false)
      expect(rdpItem!.hidden).toBe(true)
      expect(confirmBox!.hidden).toBe(false)
      expect(invokeSpy).not.toHaveBeenCalledWith('cmd_open_rdp', expect.anything())

      // 3. Clicking "Cancel" closes menu and resets state without calling cmd_open_rdp
      confirmCancelBtn!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(menu!.hidden).toBe(true)
      expect(rdpItem!.hidden).toBe(false)
      expect(confirmBox!.hidden).toBe(true)
      expect(invokeSpy).not.toHaveBeenCalledWith('cmd_open_rdp', expect.anything())

      // 4. Re-opening menu, clicking "Connect with RDP", then clicking "Connect" invokes cmd_open_rdp
      toggleBtn!.click()
      rdpItem!.click()
      expect(confirmBox!.hidden).toBe(false)
      const unpinnedEl = document.querySelector('.dv-rdp-unpinned-note') as HTMLElement | null
      expect(unpinnedEl).not.toBeNull()
      expect(unpinnedEl!.hidden).toBe(false)
      expect(unpinnedEl!.textContent).toBe(DESKTOP_RDP_UNPINNED_NOTICE)
      confirmAcceptBtn!.click()
      await new Promise((r) => setTimeout(r, 10))
      expect(menu!.hidden).toBe(true)
      expect(invokeSpy).toHaveBeenCalledTimes(1)
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_rdp', {
        target: 'node-surface-01',
        org: null,
      })
    })
  })

  describe('6. RDP over the mesh: offered only when `rdp_mesh_reachable` is true', () => {
    it('shows only the one-line hint (no connect, no auto, no auto-launch) when RDP exists but is not reachable over the mesh', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = {
        openRdp: openRdpSpy,
      }
      expect(setDeviceAutoRdpFallback(DEVICE_ID, true, true)).toBe(true)
      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'connection_timed_out',
          errorMessage: 'connection timed out',
          rdpAvailable: true,
          rdpMeshReachable: false,
          rdpPort: 3389,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })
      await nextTick()
      expect(wrapper.find('[data-test="rdp-fallback-card"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="rdp-mesh-hint"]').text()).toBe(rdpMeshDisabledHint())
      expect(wrapper.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-auto-toggle"]').exists()).toBe(false)
      expect(openRdpSpy).not.toHaveBeenCalled()
    })

    it('without the desktop bridge, shows the hint and no `mh rdp` command when not reachable', () => {
      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'connection_timed_out',
          rdpAvailable: true,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })
      expect(wrapper.find('[data-test="rdp-mesh-hint"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="rdp-fallback-no-bridge"]').exists()).toBe(false)
    })

    it('offers the RDP actions and no hint when reachable', () => {
      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'connection_timed_out',
          rdpAvailable: true,
          rdpMeshReachable: true,
          deviceId: DEVICE_ID,
          deviceName: DEVICE_NAME,
        },
      })
      expect(wrapper.find('[data-test="rdp-mesh-hint"]').exists()).toBe(false)
      expect(wrapper.find('[data-test="rdp-fallback-no-bridge"]').exists()).toBe(true)
      // No bridge, so nothing automatic can run here: the retry stays.
      expect(wrapper.find('[data-test="rdp-fallback-retry-btn"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="rdp-auto-toggle"]').exists()).toBe(false)
    })

    it('desktop menu: hint instead of "Connect with RDP" when not reachable, and no dropdown without RDP', async () => {
      const parsed = new DOMParser().parseFromString(DESKTOP_HTML, 'text/html')
      const section = document.importNode(parsed.getElementById('view-devices')!, true)
      section.hidden = false
      document.body.innerHTML = ''
      document.body.appendChild(section)
      const OTHER_ID = '66366f7a7230306d6c657299'
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
                rdp_available: true,
                rdp_mesh_reachable: false,
              },
              {
                id: OTHER_ID,
                overlay_node_id: 'node-linux-01',
                name: 'linux-box',
                kind: 'agent',
                is_self: false,
                presence: 'online',
                os: 'linux',
              },
            ],
            total: 2,
            page: 1,
            per_page: 25,
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
        get: () => ({ available: true, orgs: [{ label: 'primary', primary: true }], peers: [] }),
        currentView: () => 'devices',
        Mesh: { create: () => ({ render: () => undefined }) },
      }
      window.eval(DESKTOP_GRID_JS)
      window.eval(DESKTOP_DEVICES_JS)
      document.dispatchEvent(new Event('DOMContentLoaded'))
      document.dispatchEvent(new CustomEvent('meshharbor:view', { detail: 'devices' }))
      await new Promise((r) => setTimeout(r, 20))

      // Rows are keyed by device; an earlier test's devices.js instance may
      // render too, so select by key rather than counting widgets.
      const wrapsFor = (id: string) =>
        Array.from(document.querySelectorAll(`tr[data-key*="${id}"] .dv-split-wrap`)) as HTMLElement[]
      const surfaceWraps = wrapsFor(DEVICE_ID)
      const linuxWraps = wrapsFor(OTHER_ID)
      expect(surfaceWraps.length).toBeGreaterThan(0)
      expect(linuxWraps.length).toBeGreaterThan(0)
      const toggle1 = surfaceWraps[0].querySelector('.dv-split-toggle') as HTMLButtonElement
      const item1 = surfaceWraps[0].querySelector('.dv-split-item-rdp') as HTMLButtonElement
      const hint1 = surfaceWraps[0].querySelector('.dv-split-hint') as HTMLElement
      expect(toggle1.hidden).toBe(false)
      toggle1.click()
      expect(item1.hidden).toBe(true)
      expect(hint1.hidden).toBe(false)
      expect(hint1.textContent).toBe(DESKTOP_RDP_MESH_HINT)
      for (const w of linuxWraps) {
        expect((w.querySelector('.dv-split-toggle') as HTMLButtonElement).hidden).toBe(true)
      }
      expect(invokeSpy).not.toHaveBeenCalledWith('cmd_open_rdp', expect.anything())
    })
  })

  describe('7. RDP only when remote control cannot serve; the Windows logon is asked for once', () => {
    const base = { rdpAvailable: true }

    it('classifies why the card is up', () => {
      // The host says it cannot show a screen.
      for (const reason of ['no_display', 'backend_error', 'permission', 'media_unavailable:no_display']) {
        expect(rdpFallbackMode({ ...base, phase: 'connected', mediaUnavailableReason: reason })).toBe('unserved')
      }
      // No agent is connected to serve remote control.
      expect(rdpFallbackMode({ ...base, phase: 'error', errorCode: 'agent_offline' })).toBe('unserved')
      // A Windows lock screen the worker can neither show nor drive.
      expect(rdpFallbackMode({ ...base, phase: 'connected', hostLockedBlocked: true })).toBe('unserved')
      // An attempt that failed on the way: remote control may serve next time.
      for (const code of ['connection_timed_out', 'peer_connection_failed', 'media_stalled', 'agent_disconnect', 'internal']) {
        expect(rdpFallbackMode({ ...base, phase: 'error', errorCode: code })).toBe('failed')
      }
      // A locked host whose lock screen takes input, or that is not locked,
      // is remote control's to serve: no card.
      expect(rdpFallbackMode({ ...base, phase: 'connected', hostLockedBlocked: false })).toBe('none')
      expect(rdpFallbackMode({ ...base, phase: 'connected' })).toBe('none')
      // The lock only counts in a live session.
      expect(rdpFallbackMode({ ...base, phase: 'idle', hostLockedBlocked: true })).toBe('none')
      // Consent, policy and identity codes never lead to RDP.
      for (const code of ['consent_denied', 'agent_busy', 'permission_denied', 'peer_auth_key_changed']) {
        expect(rdpFallbackMode({ ...base, phase: 'error', errorCode: code })).toBe('none')
      }
      // No RDP server, no card, whatever the reason.
      for (const rdpAvailable of [false, null, undefined]) {
        expect(
          rdpFallbackMode({ rdpAvailable, phase: 'connected', mediaUnavailableReason: 'no_display', hostLockedBlocked: true }),
        ).toBe('none')
      }
      expect(shouldShowRdpFallbackCard({ ...base, phase: 'connected', hostLockedBlocked: true })).toBe(true)
    })

    it('decides the automatic step: RDP at once when unserved, remote control once more when failed', () => {
      const t0 = 1_000_000
      expect(nextRdpFallbackStep({ mode: 'none', nowMs: t0, lastAutoRetryAtMs: null })).toBe('none')
      expect(nextRdpFallbackStep({ mode: 'unserved', nowMs: t0, lastAutoRetryAtMs: null })).toBe('open-rdp')
      expect(nextRdpFallbackStep({ mode: 'unserved', nowMs: t0, lastAutoRetryAtMs: t0 - 1 })).toBe('open-rdp')
      expect(nextRdpFallbackStep({ mode: 'failed', nowMs: t0, lastAutoRetryAtMs: null })).toBe('retry-rc')
      // Failed again right after the retry: now RDP.
      expect(nextRdpFallbackStep({ mode: 'failed', nowMs: t0 + 5_000, lastAutoRetryAtMs: t0 })).toBe('open-rdp')
      expect(
        nextRdpFallbackStep({ mode: 'failed', nowMs: t0 + RDP_FALLBACK_RETRY_WINDOW_MS - 1, lastAutoRetryAtMs: t0 }),
      ).toBe('open-rdp')
      // A failure long after the last retry is a new one: retry first again.
      expect(
        nextRdpFallbackStep({ mode: 'failed', nowMs: t0 + RDP_FALLBACK_RETRY_WINDOW_MS, lastAutoRetryAtMs: t0 }),
      ).toBe('retry-rc')
      // A clock that went backwards never skips the retry.
      expect(nextRdpFallbackStep({ mode: 'failed', nowMs: t0 - 10, lastAutoRetryAtMs: t0 })).toBe('retry-rc')
    })

    it('a failed attempt retries remote control once by itself, and opens RDP when that fails too', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = { openRdp: openRdpSpy }
      const props = {
        phase: 'error',
        errorCode: 'peer_connection_failed',
        rdpAvailable: true,
        rdpMeshReachable: true,
        deviceId: DEVICE_ID,
        deviceName: DEVICE_NAME,
      }
      // First failure: remote control is retried, RDP is not opened, no chooser.
      const first = mount(RdpFallbackCard, { props })
      await flushPromises()
      expect(first.emitted('retry-rc')).toHaveLength(1)
      expect(openRdpSpy).not.toHaveBeenCalled()
      expect(first.find('[data-test="rdp-auto-retry-status"]').exists()).toBe(true)
      expect(first.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(false)
      expect(getLastAutoRcRetry(DEVICE_ID)).not.toBeNull()
      first.unmount()

      // The retry failed too (the page remounts the card): RDP, by itself.
      const second = mount(RdpFallbackCard, { props })
      await flushPromises()
      expect(second.emitted('retry-rc')).toBeUndefined()
      expect(openRdpSpy).toHaveBeenCalledTimes(1)
      expect(second.find('[data-test="rdp-auto-status"]').exists()).toBe(true)
      second.unmount()

      // Another device has its own retry.
      const other = mount(RdpFallbackCard, { props: { ...props, deviceId: '66366f7a7230306d6c657299' } })
      await flushPromises()
      expect(other.emitted('retry-rc')).toHaveLength(1)
      expect(openRdpSpy).toHaveBeenCalledTimes(1)
    })

    it('a retry older than the window does not count against a new failure', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = { openRdp: openRdpSpy }
      noteAutoRcRetry(DEVICE_ID, Date.now() - RDP_FALLBACK_RETRY_WINDOW_MS - 1)
      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'media_stalled',
          rdpAvailable: true,
          rdpMeshReachable: true,
          deviceId: DEVICE_ID,
        },
      })
      await flushPromises()
      expect(wrapper.emitted('retry-rc')).toHaveLength(1)
      expect(openRdpSpy).not.toHaveBeenCalled()
    })

    it('a host that cannot be served opens RDP at once: offline agent, blocked lock screen', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = { openRdp: openRdpSpy }
      const offline = mount(RdpFallbackCard, {
        props: {
          phase: 'error',
          errorCode: 'agent_offline',
          rdpAvailable: true,
          rdpMeshReachable: true,
          deviceId: DEVICE_ID,
        },
      })
      await flushPromises()
      expect(offline.emitted('retry-rc')).toBeUndefined()
      expect(openRdpSpy).toHaveBeenCalledTimes(1)
      offline.unmount()

      openRdpSpy.mockClear()
      const locked = mount(RdpFallbackCard, {
        props: {
          phase: 'connected',
          hostLockedBlocked: true,
          rdpAvailable: true,
          rdpMeshReachable: true,
          deviceId: DEVICE_ID,
        },
      })
      await flushPromises()
      expect(openRdpSpy).toHaveBeenCalledTimes(1)
      expect(locked.find('[data-test="rdp-fallback-reason"]').text()).toContain('锁屏')
      expect(locked.find('[data-test="rdp-fallback-connect-btn"]').exists()).toBe(false)

      // The lock screen takes input (SystemContext): remote control serves it.
      openRdpSpy.mockClear()
      const served = mount(RdpFallbackCard, {
        props: {
          phase: 'connected',
          hostLockedBlocked: false,
          rdpAvailable: true,
          rdpMeshReachable: true,
          deviceId: DEVICE_ID,
        },
      })
      await flushPromises()
      expect(served.find('[data-test="rdp-fallback-card"]').exists()).toBe(false)
      expect(openRdpSpy).not.toHaveBeenCalled()
    })

    it('the page never carries a password; re-entering the Windows account is one request flag', async () => {
      const openRdpSpy = vi.fn(async () => undefined)
      ;(window as unknown as Record<string, unknown>).__MESHHARBOR_DESKTOP_BRIDGE__ = { openRdp: openRdpSpy }
      const wrapper = mount(RdpFallbackCard, {
        props: {
          phase: 'connected',
          mediaUnavailableReason: 'no_display',
          rdpAvailable: true,
          rdpMeshReachable: true,
          rdpPort: 3389,
          deviceId: DEVICE_ID,
        },
      })
      await flushPromises()
      expect(openRdpSpy).toHaveBeenCalledTimes(1)
      expect(openRdpSpy.mock.calls[0]).toEqual([{ target: DEVICE_ID, org: undefined, port: 3389, certSha256: undefined }])

      await wrapper.find('[data-test="rdp-reset-credential-btn"]').trigger('click')
      await flushPromises()
      expect(openRdpSpy).toHaveBeenCalledTimes(2)
      expect(openRdpSpy.mock.calls[1]).toEqual([
        { target: DEVICE_ID, org: undefined, port: 3389, certSha256: undefined, resetCredential: true },
      ])
      for (const call of openRdpSpy.mock.calls) {
        expect(Object.keys((call as unknown[])[0] as object).sort()).not.toContain('password')
      }

      // The Tauri invoke path carries the same flag and nothing else new.
      const invokeSpy = vi.fn(async () => undefined)
      await invokeDesktopOpenRdp(
        { target: DEVICE_ID, resetCredential: true },
        { __TAURI__: { core: { invoke: invokeSpy } } },
      )
      expect(invokeSpy).toHaveBeenCalledWith('cmd_open_rdp', {
        target: DEVICE_ID,
        org: null,
        port: null,
        certSha256: null,
        resetCredential: true,
      })
    })
  })
})
