// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-116 P6a — Analytics' per-person usage on a phone.
//
// Eight columns put everything after the name behind a sideways scroll. On a
// phone the table answers "who, and how much in total"; the per-category
// minutes and traffic are one tap away — a row opens the person's detail,
// exactly as it does on the desktop.
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import type { Ref } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

const hoisted = vi.hoisted(() => ({
  // A real ref (created in the mock): a template unwraps only refs.
  xs: null as unknown as Ref<boolean>,
}))
vi.mock('vuetify', async (importOriginal) => {
  const actual = await importOriginal<typeof import('vuetify')>()
  const { ref } = await import('vue')
  hoisted.xs = ref(false)
  return { ...actual, useDisplay: () => ({ xs: hoisted.xs }) }
})

import UsageTable from '@/components/stats/UsageTable.vue'
import type { UsageUserRow } from '@/stores/stats'

const vuetify = createVuetify({ components, directives })

beforeAll(() => {
  const g = globalThis as unknown as Record<string, unknown>
  if (!('ResizeObserver' in g)) {
    g.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  }
})

const cls = (minutes: number, bytes: number) => ({
  minutes,
  bytes,
  sessions: 1,
  devices: 1,
  bytes_known: bytes > 0,
})
const users: UsageUserRow[] = [
  { user_id: 'u1', name: 'Sam Support', rc: cls(1204, 9e9), tunnel: cls(0, 0), total_minutes: 1204 },
  { user_id: 'u2', name: 'Alex Admin', rc: cls(312, 4e9), tunnel: cls(44, 2e8), total_minutes: 356 },
]

function mountAt(width: 'phone' | 'wide') {
  hoisted.xs.value = width === 'phone'
  return mount(UsageTable, { props: { users }, global: { plugins: [vuetify] } })
}

const headerTitles = (w: ReturnType<typeof mountAt>) =>
  w.findAll('thead th').map((th) => th.text()).filter(Boolean)

describe('UsageTable (FR-116 P6a)', () => {
  it('on a phone: who, and how much in total', () => {
    const w = mountAt('phone')
    expect(headerTitles(w)).toEqual(['User', 'Total'])
    expect(w.text()).toContain('tap one for the breakdown')
  })

  it('a tapped row still opens the person — the breakdown is there, on demand', async () => {
    const w = mountAt('phone')
    await w.find('tbody tr').trigger('click')
    expect(w.emitted('select')).toEqual([['u1']])
  })

  it('from 600 px up: every column, as before', () => {
    const w = mountAt('wide')
    expect(headerTitles(w)).toEqual(['User', 'Remote desktop', 'Tunnel', 'Total'])
    expect(w.text()).not.toContain('tap one for the breakdown')
  })
})
