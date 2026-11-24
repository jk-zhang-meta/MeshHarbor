// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import i18n, { setLocale } from '@/plugins/i18n'
import { lightTheme, darkTheme } from '@/plugins/vuetify'
import {
  isEmbedChromeHidden,
  parseEmbedFlag,
  parseLangParam,
  parseThemeParam,
  resolveThemeMode,
} from '@/views/network/globeEmbedParams'

const mockFetchMesh = vi.fn(() => Promise.resolve(null))
const mockFetchAgents = vi.fn(() => Promise.resolve())

vi.mock('@/stores/stats', () => ({
  useStatsStore: () => ({
    mesh: {
      enabled: true,
      center: { id: 'centre-1', name: 'centre.example.test', country_code: 'DE' },
      nodes: [
        {
          id: 'node-1',
          agent_id_hex: '65f000000000000000000011',
          name: 'device-a',
          overlay_ip: '100.64.0.10',
        },
      ],
      agents: [
        {
          id: '65f000000000000000000011',
          name: 'device-a',
          last_presence: 'online',
          os: 'linux',
          agent_version: '0.5.0',
          management_path: { mode: 'direct' },
        },
      ],
      edges: [],
    },
    fetchMesh: mockFetchMesh,
  }),
}))

vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({
    agents: [
      {
        id: '65f000000000000000000011',
        name: 'device-a',
        display_name: 'Device A',
        is_online: true,
        presence: 'online',
        country_code: 'CN',
        city: 'Beijing',
        public_ip: '192.0.2.10',
      },
    ],
    fetchAgents: mockFetchAgents,
  }),
}))

vi.mock('@/stores/tenant', () => ({
  useTenantStore: () => ({
    current: { id: '65f000000000000000000001', name: 'Acme', slug: 'acme' },
    tenants: [{ id: '65f000000000000000000001', name: 'Acme', slug: 'acme' }],
    myPermissions: null,
    isOwner: true,
    fetchTenants: vi.fn(() => Promise.resolve()),
    fetchMyMembership: vi.fn(() => Promise.resolve()),
    setCurrent: vi.fn(),
  }),
}))

vi.mock('@/stores/capabilities', () => ({
  useCapabilitiesStore: () => ({
    has: () => true,
    ready: () => Promise.resolve(),
    load: () => Promise.resolve(),
  }),
}))

vi.mock('@/components/globe/webgl', () => ({
  isWebGL2Supported: () => true,
}))

// Lightweight stub for MeshGlobeMap so jsdom tests verify exact props & embed behavior without WebGL.
vi.mock('@/components/globe-v2/MeshGlobeMap.vue', async () => {
  const { defineComponent, h } = await import('vue')
  return {
    default: defineComponent({
      name: 'MeshGlobeMap',
      props: {
        nodes: { type: Array, required: true },
        arcs: { type: Array, required: true },
        center: { type: Object, default: null },
        themeMode: { type: String, required: true },
        lang: { type: String, required: true },
        standaloneFullPage: { type: Boolean, default: false },
        showOpenDeviceAction: { type: Boolean, default: true },
      },
      emits: ['open-device', 'webgl-error'],
      setup(props) {
        return () =>
          h('div', {
            'data-testid': 'mesh-globe-map-stub',
            'data-theme-mode': props.themeMode,
            'data-lang': props.lang,
            'data-standalone': props.standaloneFullPage ? '1' : '0',
            'data-node-count': String(props.nodes.length),
          })
      },
    }),
  }
})

import NetworkGlobeView from '@/views/network/NetworkGlobeView.vue'
import realRouter from '@/plugins/router'
import { clearSignedIn, markSignedIn } from '@/api/session'

function createMatchMediaStub(initialDark: boolean) {
  let matches = initialDark
  const listeners = new Set<(e: MediaQueryListEvent) => void>()
  const mql = {
    media: '(prefers-color-scheme: dark)',
    get matches() {
      return matches
    },
    addEventListener: (_type: string, cb: (e: MediaQueryListEvent) => void) => {
      listeners.add(cb)
    },
    removeEventListener: (_type: string, cb: (e: MediaQueryListEvent) => void) => {
      listeners.delete(cb)
    },
  }
  return {
    matchMedia: vi.fn(() => mql),
    setDark(next: boolean) {
      matches = next
      for (const cb of listeners) {
        cb({ matches: next } as MediaQueryListEvent)
      }
    },
  }
}

describe('globeEmbedParams helpers', () => {
  it('parses ?embed=1 strictly', () => {
    expect(parseEmbedFlag('1')).toBe(true)
    expect(parseEmbedFlag(['1', '0'])).toBe(true)
    expect(parseEmbedFlag('0')).toBe(false)
    expect(parseEmbedFlag('true')).toBe(false)
    expect(parseEmbedFlag(undefined)).toBe(false)
  })

  it('parses lang=en* and lang=zh* cleanly and ignores unknown values', () => {
    expect(parseLangParam('en')).toBe('en')
    expect(parseLangParam('EN-US')).toBe('en')
    expect(parseLangParam('zh')).toBe('zh-CN')
    expect(parseLangParam('zh-CN')).toBe('zh-CN')
    expect(parseLangParam('zh_Hans')).toBe('zh-CN')
    expect(parseLangParam('zh-TW')).toBe('zh-CN')
    expect(parseLangParam('fr-FR')).toBeNull()
    expect(parseLangParam('')).toBeNull()
    expect(parseLangParam(undefined)).toBeNull()
  })

  it('parses and resolves theme=light|dark|system', () => {
    expect(parseThemeParam('light')).toBe('light')
    expect(parseThemeParam('DARK')).toBe('dark')
    expect(parseThemeParam('system')).toBe('system')
    expect(parseThemeParam('invalid')).toBeNull()

    expect(resolveThemeMode('light', true, true)).toBe('light')
    expect(resolveThemeMode('dark', false, false)).toBe('dark')
    expect(resolveThemeMode('system', true, false)).toBe('dark')
    expect(resolveThemeMode('system', false, true)).toBe('light')
    expect(resolveThemeMode(null, true, false)).toBe('light')
    expect(resolveThemeMode(null, false, true)).toBe('dark')
  })

  it('hides chrome only when route allows embed and ?embed=1 is set', () => {
    expect(isEmbedChromeHidden({ meta: { allowEmbed: true }, query: { embed: '1' } })).toBe(true)
    expect(isEmbedChromeHidden({ meta: { allowEmbed: true }, query: {} })).toBe(false)
    expect(isEmbedChromeHidden({ meta: { allowEmbed: false }, query: { embed: '1' } })).toBe(false)
    expect(isEmbedChromeHidden({ meta: {}, query: { embed: '1' } })).toBe(false)
  })
})

describe('NetworkGlobeView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    sessionStorage.clear()
    setLocale('en')
    mockFetchMesh.mockClear()
    mockFetchAgents.mockClear()
  })

  afterEach(() => {
    setLocale('en')
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  async function mountView(url: string, initialSystemDark = false) {
    const mm = createMatchMediaStub(initialSystemDark)
    vi.stubGlobal('matchMedia', mm.matchMedia)
    const vuetify = createVuetify({
      components,
      directives,
      theme: {
        defaultTheme: 'light',
        themes: { light: lightTheme, dark: darkTheme },
      },
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: '/tenant/:tenantId/network/globe',
          name: 'network-globe',
          component: NetworkGlobeView,
          meta: { module: 'network', allowEmbed: true },
        },
        {
          path: '/tenant/:tenantId/devices',
          name: 'devices',
          component: { template: '<div />' },
        },
      ],
    })
    await router.push(url)
    await router.isReady()
    const wrapper = mount(NetworkGlobeView, {
      global: { plugins: [vuetify, router, createPinia(), i18n] },
    })
    await flushPromises()
    return { wrapper, vuetify, router, mm }
  }

  it('honours ?embed=1&lang=zh-CN&theme=dark without clobbering saved localStorage locale', async () => {
    localStorage.setItem('meshharbor.locale', 'en')
    const { wrapper, vuetify } = await mountView(
      '/tenant/65f000000000000000000001/network/globe?embed=1&lang=zh-CN&theme=dark',
    )
    const root = wrapper.get('[data-testid="network-globe-view"]')
    expect(root.attributes('data-embed')).toBe('1')
    expect(root.classes()).toContain('mh-network-globe-view--embed')
    expect(root.attributes('data-lang')).toBe('zh-CN')
    expect(root.attributes('data-theme')).toBe('dark')
    expect(vuetify.theme.global.current.value.dark).toBe(true)
    expect(String(i18n.global.locale.value)).toBe('zh-CN')
    expect(localStorage.getItem('meshharbor.locale')).toBe('en')

    const stub = wrapper.get('[data-testid="mesh-globe-map-stub"]')
    expect(stub.attributes('data-theme-mode')).toBe('dark')
    expect(stub.attributes('data-lang')).toBe('zh-CN')
    expect(stub.attributes('data-standalone')).toBe('1')
    expect(stub.attributes('data-node-count')).toBe('1')
    expect(mockFetchMesh).toHaveBeenCalledWith('65f000000000000000000001')
    expect(mockFetchAgents).toHaveBeenCalledWith('65f000000000000000000001')
    wrapper.unmount()
  })

  it('honours ?embed=1&lang=en&theme=light and works without ?embed=1', async () => {
    const { wrapper, vuetify } = await mountView(
      '/tenant/65f000000000000000000001/network/globe?lang=en&theme=light',
    )
    const root = wrapper.get('[data-testid="network-globe-view"]')
    expect(root.attributes('data-embed')).toBe('0')
    expect(root.classes()).not.toContain('mh-network-globe-view--embed')
    expect(root.attributes('data-lang')).toBe('en')
    expect(root.attributes('data-theme')).toBe('light')
    expect(vuetify.theme.global.current.value.dark).toBe(false)
    wrapper.unmount()
  })

  it('resolves ?theme=system reactively against prefers-color-scheme changes', async () => {
    const { wrapper, vuetify, mm } = await mountView(
      '/tenant/65f000000000000000000001/network/globe?embed=1&lang=en&theme=system',
      false,
    )
    expect(wrapper.get('[data-testid="mesh-globe-map-stub"]').attributes('data-theme-mode')).toBe('light')
    expect(vuetify.theme.global.current.value.dark).toBe(false)

    mm.setDark(true)
    await flushPromises()
    expect(wrapper.get('[data-testid="mesh-globe-map-stub"]').attributes('data-theme-mode')).toBe('dark')
    expect(vuetify.theme.global.current.value.dark).toBe(true)

    mm.setDark(false)
    await flushPromises()
    expect(wrapper.get('[data-testid="mesh-globe-map-stub"]').attributes('data-theme-mode')).toBe('light')
    expect(vuetify.theme.global.current.value.dark).toBe(false)
    wrapper.unmount()
  })
})

describe('router auth guard — /tenant/:tenantId/network/globe redirect preservation', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    clearSignedIn()
    sessionStorage.clear()
  })

  afterEach(() => {
    clearSignedIn()
    sessionStorage.clear()
  })

  it('preserves full ?embed=1&lang=...&theme=... across signed-out redirect and returns after sign-in', async () => {
    const target = '/tenant/65f000000000000000000001/network/globe?embed=1&lang=zh-CN&theme=dark'

    // 1. Signed out -> redirected to login with exact target stashed in pending_redirect
    await realRouter.push(target)
    await realRouter.isReady()
    expect(realRouter.currentRoute.value.name).toBe('login')
    expect(sessionStorage.getItem('pending_redirect')).toBe(target)

    // 2. Signed in -> navigating to guest route (login) consumes pending_redirect and lands on exact embed URL
    markSignedIn()
    await realRouter.push({ name: 'login', query: { from: 'return' } })
    await flushPromises()
    expect(realRouter.currentRoute.value.name).toBe('network-globe')
    expect(realRouter.currentRoute.value.fullPath).toBe(target)
    expect(realRouter.currentRoute.value.meta.allowEmbed).toBe(true)
    expect(isEmbedChromeHidden(realRouter.currentRoute.value)).toBe(true)
    expect(sessionStorage.getItem('pending_redirect')).toBeNull()
  })
})
