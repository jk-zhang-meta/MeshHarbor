// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createMemoryHistory, createRouter } from 'vue-router'

const hoisted = vi.hoisted(() => ({
  auth: { user: { id: 'u1', email: 'user@meshharbor.invalid' } },
  tenant: {
    tenants: [] as Array<{ id: string; name: string; slug: string; description?: string }>,
    fetchTenants: vi.fn(),
    createTenant: vi.fn(),
  },
  newsletter: {
    subscribed: { value: true },
    busy: { value: false },
    load: vi.fn(),
    set: vi.fn(),
  },
  snackbar: {
    showSuccess: vi.fn(),
    showError: vi.fn(),
  },
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => hoisted.auth,
}))
vi.mock('@/stores/tenant', () => ({
  useTenantStore: () => hoisted.tenant,
}))
vi.mock('@/composables/useNewsletterPref', async () => {
  const { ref } = await import('vue')
  return {
    useNewsletterPref: () => ({
      subscribed: ref(true),
      busy: ref(false),
      load: hoisted.newsletter.load,
      set: hoisted.newsletter.set,
    }),
  }
})
vi.mock('@/composables/useSnackbar', () => ({
  useSnackbar: () => hoisted.snackbar,
}))

import DashboardView from '@/views/dashboard/DashboardView.vue'

const vuetify = createVuetify({ components, directives })

async function mountDashboard() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'dashboard', component: DashboardView },
      { path: '/tenant/:tenantId', name: 'tenant', component: { template: '<div />' } },
    ],
  })
  await router.push('/')
  await router.isReady()
  const wrapper = mount(DashboardView, {
    global: { plugins: [vuetify, router] },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
  hoisted.tenant.tenants = []
  hoisted.tenant.fetchTenants.mockReset().mockResolvedValue(undefined)
  hoisted.tenant.createTenant
    .mockReset()
    .mockImplementation(async (name: string, slug: string) => ({ id: 't-new', name, slug }))
  hoisted.snackbar.showSuccess.mockReset()
  hoisted.snackbar.showError.mockReset()
})

describe('DashboardView — empty-state workspace form autoSlug & slugTouched', () => {
  it('auto-populates slug from workspace name in the zero-org form and creates the workspace', async () => {
    const wrapper = await mountDashboard()
    const inputs = wrapper.findAll('input')
    expect(inputs.length).toBeGreaterThanOrEqual(2)

    await inputs[0]!.setValue('Acme Mesh Lab!')
    await flushPromises()
    expect((inputs[1]!.element as HTMLInputElement).value).toBe('acme-mesh-lab')

    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(hoisted.tenant.createTenant).toHaveBeenCalledWith('Acme Mesh Lab!', 'acme-mesh-lab')
  })

  it('stops overwriting slug once the user edits the slug field in the zero-org form', async () => {
    const wrapper = await mountDashboard()
    const inputs = wrapper.findAll('input')
    expect(inputs.length).toBeGreaterThanOrEqual(2)

    await inputs[0]!.setValue('Initial Name')
    await flushPromises()
    expect((inputs[1]!.element as HTMLInputElement).value).toBe('initial-name')

    await inputs[1]!.setValue('custom-slug')
    await flushPromises()

    await inputs[0]!.setValue('Renamed Workspace')
    await flushPromises()
    expect((inputs[1]!.element as HTMLInputElement).value).toBe('custom-slug')
  })
})
