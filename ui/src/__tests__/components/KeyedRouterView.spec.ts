// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// #1631 — the remote view must FOLLOW the device in the URL. Vue Router
// reuses a mounted component when only a param changes, so
// /agent/A/remote → /agent/B/remote kept A's viewer (toolbar, status, and
// Connect dialling A) under B's URL. `KeyedRouterView` keys the routed
// component by the param its route names in `meta.remountOn`.
//
// These specs run against the REAL route records (`router.options.routes`
// from `@/plugins/router`), with the heavy views stubbed by counters, so a
// record that loses — or gains — `remountOn` fails here rather than in the
// field. The routes that must NOT remount are locked too: several views
// rewrite `route.query` in place via `router.replace` and would be torn down
// on every filter flip by a fullPath key.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import {
  createMemoryHistory,
  createRouter,
  RouterView,
  type RouteRecordRaw,
  type Router,
} from 'vue-router'
import router from '@/plugins/router'
import KeyedRouterView from '@/components/layout/KeyedRouterView.vue'
import { routeViewKey } from '@/plugins/routeViewKey'

// Hoisted so the `vi.mock` factories below (which Vitest lifts above every
// import) can reach them. Each stub counts its setups and unmounts; a
// remount is one of each, a reuse is neither.
const { counters, stubModule } = vi.hoisted(() => {
  const make = () => ({ setups: 0, unmounts: 0 })
  const counters = { remote: make(), devices: make(), profile: make(), dashboard: make() }
  async function stubModule(which: keyof typeof counters) {
    const { defineComponent, h, onUnmounted } = await import('vue')
    return {
      default: defineComponent({
        name: `${which}-stub`,
        setup() {
          counters[which].setups += 1
          onUnmounted(() => {
            counters[which].unmounts += 1
          })
          return () => h('div', { 'data-stub': which })
        },
      }),
    }
  }
  return { counters, stubModule }
})

vi.mock('@/views/remote/RemoteControl.vue', () => stubModule('remote'))
vi.mock('@/views/devices/DevicesView.vue', () => stubModule('devices'))
vi.mock('@/views/profile/ProfileView.vue', () => stubModule('profile'))
// The `/` child. Never navigated to here (the first target is pushed before
// the app mounts), but the real view needs Pinia and would wreck the render
// tree for every later patch if a test ever landed on it.
vi.mock('@/views/dashboard/DashboardView.vue', () => stubModule('dashboard'))

/** The app layout's child records, exactly as the SPA registers them. */
function layoutChildren(): RouteRecordRaw[] {
  const layout = router.options.routes.find((r) => r.path === '/' && Array.isArray(r.children))
  if (!layout?.children) throw new Error('the AppLayout route record moved — update this spec')
  return layout.children
}

let wrapper: VueWrapper | null = null

/** Mount the keyed view with the router already AT `initial` (pushed before
 *  the app mounts, so the install-time initial navigation never lands on
 *  `/`), and return the router to navigate with. */
async function mountKeyed(initial: string): Promise<Router> {
  const mem = createRouter({
    history: createMemoryHistory(),
    // KeyedRouterView stands in for AppLayout: its inner <router-view> is
    // the one AppLayout.vue renders the page into, so the depth (and the
    // component-less `tenant/:tenantId` parent Vue Router skips) is the same.
    routes: [{ path: '/', component: KeyedRouterView, children: layoutChildren() }],
  })
  await mem.push(initial)
  wrapper = mount({ render: () => h(RouterView) }, { global: { plugins: [mem] } })
  await flushPromises()
  return mem
}

async function go(mem: Router, to: Parameters<Router['push']>[0]) {
  await mem.push(to)
  await flushPromises()
}

describe('KeyedRouterView over the real route records (#1631)', () => {
  beforeEach(() => {
    for (const c of Object.values(counters)) {
      c.setups = 0
      c.unmounts = 0
    }
  })
  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('remounts the remote view when the agentId changes: A → B is 2 setups, 1 unmount', async () => {
    const mem = await mountKeyed('/tenant/t1/agent/agentA/remote')
    expect(counters.remote).toEqual({ setups: 1, unmounts: 0 })

    await go(mem, '/tenant/t1/agent/agentB/remote')
    // Without the key this reads {setups: 1, unmounts: 0}: the mounted view
    // is re-pointed at B's URL and keeps A's device.
    expect(counters.remote).toEqual({ setups: 2, unmounts: 1 })
  })

  it('does NOT remount the remote view on a query-only replace (the in-place query-rewrite pattern)', async () => {
    const mem = await mountKeyed('/tenant/t1/agent/agentA/remote')
    expect(counters.remote.setups).toBe(1)

    await mem.replace({ query: { x: '1' } })
    await flushPromises()
    expect(mem.currentRoute.value.fullPath).toBe('/tenant/t1/agent/agentA/remote?x=1')
    expect(counters.remote).toEqual({ setups: 1, unmounts: 0 })
  })

  it('leaves a route without remountOn on the plain reuse: devices t1 → t2 is one setup, no unmount', async () => {
    const mem = await mountKeyed('/tenant/t1/devices')
    expect(counters.devices).toEqual({ setups: 1, unmounts: 0 })
    await go(mem, '/tenant/t2/devices')
    // DevicesView watches tenantId itself; a remount here would be a regression
    // for every view that manages its own param changes.
    expect(counters.devices).toEqual({ setups: 1, unmounts: 0 })
  })

  it('remounts the profile view when the userId changes', async () => {
    const mem = await mountKeyed('/profile/u1')
    expect(counters.profile).toEqual({ setups: 1, unmounts: 0 })
    await go(mem, '/profile/u2')
    expect(counters.profile).toEqual({ setups: 2, unmounts: 1 })
  })

  it('the record itself carries the contract: agent-remote keys on agentId, profile on userId, devices on nothing', () => {
    const byName = new Map<string, RouteRecordRaw>()
    const walk = (rs: readonly RouteRecordRaw[]) => {
      for (const r of rs) {
        if (typeof r.name === 'string') byName.set(r.name, r)
        if (r.children) walk(r.children)
      }
    }
    walk(router.options.routes)
    expect(byName.get('agent-remote')?.meta?.remountOn).toBe('agentId')
    expect(byName.get('profile')?.meta?.remountOn).toBe('userId')
    expect(byName.get('devices')?.meta?.remountOn).toBeUndefined()
  })
})

describe('routeViewKey', () => {
  const routeLike = (over: Record<string, unknown>) =>
    ({
      name: 'agent-remote',
      params: { tenantId: 't1', agentId: 'A' },
      meta: {},
      fullPath: '/tenant/t1/agent/A/remote',
      ...over,
    }) as unknown as Parameters<typeof routeViewKey>[0]

  it('is undefined without meta.remountOn — the same as no key at all', () => {
    expect(routeViewKey(routeLike({}))).toBeUndefined()
    expect(routeViewKey(routeLike({ meta: { module: 'remote' } }))).toBeUndefined()
  })

  it('is name:param with it, and ignores the query', () => {
    expect(routeViewKey(routeLike({ meta: { remountOn: 'agentId' } }))).toBe('agent-remote:A')
    expect(
      routeViewKey(
        routeLike({ meta: { remountOn: 'agentId' }, fullPath: '/tenant/t1/agent/A/remote?x=1' }),
      ),
    ).toBe('agent-remote:A')
    expect(
      routeViewKey(routeLike({ meta: { remountOn: 'agentId' }, params: { tenantId: 't1', agentId: 'B' } })),
    ).toBe('agent-remote:B')
  })

  it('tolerates a missing param value', () => {
    expect(routeViewKey(routeLike({ meta: { remountOn: 'nope' } }))).toBe('agent-remote:')
  })
})
