// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// The Devices page's one action menu, shared by the desktop grid and the
// phone cards. Each used to carry its own copy: the phone's had lost "Edit
// name & tags", and its two overlay links had lost the tenant id
// (`/tenant//network/acl`).
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createMemoryHistory, createRouter } from 'vue-router'
import DeviceActionsMenu from '@/components/admin/DeviceActionsMenu.vue'
import type { Agent } from '@/stores/agents'
import type { DeviceRow } from '@/stores/devices'
import type { OverlayNode } from '@/stores/overlayRoutes'
import type { TunnelClient } from '@/stores/tunnelClients'

const vuetify = createVuetify({ components, directives })
const router = createRouter({
  history: createMemoryHistory(),
  routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div />' } }],
})

beforeAll(() => {
  // Vuetify overlays measure themselves against the viewport; jsdom has
  // neither a ResizeObserver nor a visualViewport.
  const g = globalThis as unknown as Record<string, unknown>
  if (!('ResizeObserver' in g)) {
    g.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  }
  if (!('visualViewport' in g)) {
    g.visualViewport = {
      width: 390,
      height: 844,
      offsetLeft: 0,
      offsetTop: 0,
      pageLeft: 0,
      pageTop: 0,
      scale: 1,
      addEventListener() {},
      removeEventListener() {},
    }
  }
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  document.body.innerHTML = ''
})

const TID = 'aaaaaaaaaaaaaaaaaaaaaaaa'

function row(over: Partial<DeviceRow> = {}): DeviceRow {
  return {
    kind: 'agent',
    id: 'c00000000000000000000001',
    owner_user_id: 'u1',
    name: 'build-01',
    display_name: 'Build Server',
    machine_id: 'm1',
    os: 'linux',
    version: '0.4.146',
    status: 'online',
    presence: 'online',
    is_online: true,
    last_seen_at: '2026-10-19T12:00:00Z',
    created_at: '2026-09-01T12:00:00Z',
    ...over,
  }
}

const node = { id: 'd00000000000000000000001', name: 'build-01', will_rejoin: true } as OverlayNode

interface MenuProps {
  row: DeviceRow
  agent?: Agent
  client?: TunnelClient
  node?: OverlayNode
  networkMounted?: boolean
  canManageAgents?: boolean
  canAssignZone?: boolean
  isAdmin?: boolean
  updateBlocked?: string
}

async function openMenu(props: MenuProps) {
  wrapper = mount(DeviceActionsMenu, {
    props: { tenantId: TID, ...props },
    global: { plugins: [vuetify, router] },
    attachTo: document.body,
  })
  await wrapper.find('button').trigger('click')
  await flushPromises()
  return [...document.body.querySelectorAll('.v-list-item')] as HTMLElement[]
}

function titles(items: HTMLElement[]): string[] {
  return items.map((i) => i.querySelector('.v-list-item-title')?.textContent?.trim() ?? '')
}

describe('DeviceActionsMenu', () => {
  it('names the device in its button label by the name a person knows it by', () => {
    wrapper = mount(DeviceActionsMenu, {
      props: { tenantId: TID, row: row(), agent: { id: 'a' } as Agent },
      global: { plugins: [vuetify, router] },
    })
    expect(wrapper.find('button').attributes('aria-label')).toBe('Actions for Build Server')
  })

  it('offers an agent every standard action, Edit name & tags and Zone assignment included, while hiding Admin-only Relay policy by default', async () => {
    const items = await openMenu({ row: row(), agent: { id: 'a' } as Agent, node, networkMounted: true })
    expect(titles(items)).toEqual([
      'Update now',
      'Rotate overlay key…',
      'Crash reports',
      'Agent logs',
      'Device console',
      'Edit name & tags',
      'Mark as GPU server',
      'Add to another organization',
      'Reassign owner',
      'Execution policy',
      'SSH policy',
      'Two-factor (2FA)',
      'External access',
      'Device configuration',
      'Zone assignment',
      'Tunnel mesh routes',
      'Evict / reassign overlay address',
      'Overlay routes',
      'Overlay ACL',
      'Delete device',
    ])
  })

  it('offers Relay node policy only to Administrators (isAdmin: true) and gates Zone assignment on canAssignZone (MANAGE_AGENTS; FR-124: never mere ownership)', async () => {
    const adminItems = await openMenu({
      row: row(),
      agent: { id: 'a' } as Agent,
      node,
      networkMounted: true,
      isAdmin: true,
    })
    expect(titles(adminItems)).toContain('Zone assignment')
    expect(titles(adminItems)).toContain('Relay node policy')
    adminItems.find((i) => i.textContent?.includes('Zone assignment'))!.click()
    adminItems.find((i) => i.textContent?.includes('Relay node policy'))!.click()
    expect(wrapper!.emitted('action')).toEqual([['zone-assignment'], ['peer-relay-policy']])

    // A caller the page grants `canAssignZone` without `canManageAgents`
    // sees Zone assignment, never Relay node policy!
    wrapper!.unmount()
    document.body.innerHTML = ''
    const ownerItems = await openMenu({
      row: row(),
      agent: { id: 'a' } as Agent,
      node,
      networkMounted: true,
      canManageAgents: false,
      canAssignZone: true,
      isAdmin: false,
    })
    expect(titles(ownerItems)).toContain('Zone assignment')
    expect(titles(ownerItems)).not.toContain('Relay node policy')
    ownerItems.find((i) => i.textContent?.includes('Zone assignment'))!.click()
    expect(wrapper!.emitted('action')).toEqual([['zone-assignment']])

    // An ordinary member (`canManageAgents: false, canAssignZone: false`), owner or not,
    // sees neither Zone assignment nor Relay node policy!
    wrapper!.unmount()
    document.body.innerHTML = ''
    const nonOwnerItems = await openMenu({
      row: row(),
      agent: { id: 'a' } as Agent,
      node,
      networkMounted: true,
      canManageAgents: false,
      canAssignZone: false,
      isAdmin: false,
    })
    expect(titles(nonOwnerItems)).not.toContain('Zone assignment')
    expect(titles(nonOwnerItems)).not.toContain('Relay node policy')
  })

  it('keeps the tenant id in both overlay links', async () => {
    const items = await openMenu({ row: row(), agent: { id: 'a' } as Agent, node, networkMounted: true })
    const hrefs = items.map((i) => i.getAttribute('href')).filter(Boolean)
    expect(hrefs).toEqual([
      `/tenant/${TID}/network/subnet-routes?node=${node.id}`,
      `/tenant/${TID}/network/acl?tab=overlay`,
    ])
    expect(hrefs.join(' ')).not.toContain('/tenant//')
  })

  it('leaves out what the server does not mount (FR-69 P9)', async () => {
    const items = await openMenu({ row: row(), agent: { id: 'a' } as Agent, networkMounted: false })
    expect(titles(items)).not.toContain('Rotate overlay key…')
    expect(titles(items)).not.toContain('SSH policy')
    // No overlay node: nothing to evict, no node to filter the routes by.
    expect(titles(items)).not.toContain('Evict / reassign overlay address')
    expect(titles(items)).not.toContain('Overlay routes')
  })

  it('says why Update now will not take, and greys it', async () => {
    const items = await openMenu({
      row: row(),
      agent: { id: 'a' } as Agent,
      updateBlocked: 'auto-update is off on the device',
    })
    const update = items.find((i) => i.textContent?.includes('Update now'))!
    expect(update.textContent).toContain('auto-update is off on the device')
    expect(update.className).toContain('v-list-item--disabled')
  })

  it('renders no menu for an agent row whose full record has not loaded', () => {
    wrapper = mount(DeviceActionsMenu, {
      props: { tenantId: TID, row: row() },
      global: { plugins: [vuetify, router] },
    })
    expect(wrapper.find('button').exists()).toBe(false)
  })

  it('gives a tunnel client its own short menu, Edit name & tags included', async () => {
    const items = await openMenu({
      row: row({ kind: 'tunnel_client', name: 'neo-laptop', display_name: 'My laptop' }),
      client: { id: 'c' } as TunnelClient,
      node,
    })
    expect(titles(items)).toEqual([
      'Edit name & tags',
      'Evict / reassign overlay address',
      'Delete tunnel client',
    ])
  })

  // FR-129 — the device checks the code, so the entry needs a device that
  // understands two-factor; one that already has it on stays reachable.
  it('greys Two-factor on a device that predates it, and matches the verb by equality', async () => {
    for (const rpc of [undefined, [], ['two-factor-x', 'ssh']]) {
      const items = await openMenu({
        row: row(),
        agent: { id: 'a', capabilities: { rpc } } as unknown as Agent,
      })
      const tfa = items.find((i) => i.textContent?.includes('Two-factor (2FA)'))!
      expect(tfa.className).toContain('v-list-item--disabled')
      expect(tfa.textContent).toContain('Update the device first')
      wrapper!.unmount()
      wrapper = null
      document.body.innerHTML = ''
    }
  })

  it('opens Two-factor on a device that supports it, and says when it is on', async () => {
    let items = await openMenu({
      row: row(),
      agent: { id: 'a', capabilities: { rpc: ['exec', 'two-factor'] } } as unknown as Agent,
    })
    let tfa = items.find((i) => i.textContent?.includes('Two-factor (2FA)'))!
    expect(tfa.className).not.toContain('v-list-item--disabled')
    expect(tfa.textContent).not.toContain('On')
    tfa.click()
    expect(wrapper!.emitted('action')).toEqual([['two-factor']])
    wrapper!.unmount()
    document.body.innerHTML = ''

    // On, even where the verb is missing (an agent rolled back): it must stay
    // reachable to be switched off.
    items = await openMenu({
      row: row(),
      agent: { id: 'a', capabilities: { two_factor: true } } as unknown as Agent,
    })
    tfa = items.find((i) => i.textContent?.includes('Two-factor (2FA)'))!
    expect(tfa.className).not.toContain('v-list-item--disabled')
    expect(tfa.textContent).toContain('On')
  })

  it('says which action was picked, and nothing more', async () => {
    const items = await openMenu({ row: row(), agent: { id: 'a' } as Agent, node, networkMounted: true })
    items.find((i) => i.textContent?.includes('Edit name'))!.click()
    items.find((i) => i.textContent?.includes('Delete device'))!.click()
    expect(wrapper!.emitted('action')).toEqual([['edit'], ['delete']])
  })
})
