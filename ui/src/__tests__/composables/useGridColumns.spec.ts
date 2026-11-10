// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it } from 'vitest'
import { computed, ref } from 'vue'
import { useGridColumns } from '@/composables/useGridColumns'

const HEADERS = [
  { title: 'Actions', key: 'actions', sortable: false },
  { title: 'Name', key: 'name' },
  { title: 'Kind', key: 'kind' },
  { title: 'OS', key: 'os' },
]

function fresh(scope = 'u1:t1') {
  return useGridColumns({
    headers: computed(() => HEADERS),
    gridId: 'devices',
    scope: () => scope,
  })
}

describe('useGridColumns', () => {
  beforeEach(() => localStorage.clear())

  it('defaults to the catalog order, nothing hidden, not customized', () => {
    const g = fresh()
    expect(g.effectiveHeaders.value.map((h: any) => h.key)).toEqual([
      'actions',
      'name',
      'kind',
      'os',
    ])
    expect(g.customized.value).toBe(false)
  })

  it('toggle hides and persists; actions is locked', () => {
    const g = fresh()
    g.toggle('kind')
    expect(g.effectiveHeaders.value.map((h: any) => h.key)).toEqual(['actions', 'name', 'os'])
    g.toggle('actions') // locked — no-op
    expect(g.effectiveHeaders.value.map((h: any) => h.key)).toContain('actions')
    // A new instance with the same scope reloads the preference.
    const g2 = fresh()
    expect(g2.effectiveHeaders.value.map((h: any) => h.key)).toEqual(['actions', 'name', 'os'])
    expect(g2.customized.value).toBe(true)
    // A DIFFERENT scope (other user/org) is unaffected.
    const g3 = fresh('u2:t1')
    expect(g3.effectiveHeaders.value.map((h: any) => h.key)).toHaveLength(4)
  })

  it('reorder persists the full order; reset clears the stored key', () => {
    const g = fresh()
    g.reorder(['os', 'actions', 'name', 'kind'])
    expect(g.effectiveHeaders.value.map((h: any) => h.key)).toEqual([
      'os',
      'actions',
      'name',
      'kind',
    ])
    expect(localStorage.getItem('meshharbor:grid-cols:u1:t1:devices')).toBeTruthy()
    g.reset()
    expect(g.effectiveHeaders.value.map((h: any) => h.key)).toEqual([
      'actions',
      'name',
      'kind',
      'os',
    ])
    expect(localStorage.getItem('meshharbor:grid-cols:u1:t1:devices')).toBeNull()
  })

  it('a column shipped AFTER the user customized splices in at its catalog position', () => {
    // User saved an order over the old 4-column catalog…
    localStorage.setItem(
      'meshharbor:grid-cols:u1:t1:devices',
      JSON.stringify({ order: ['os', 'actions', 'name', 'kind'], hidden: [] }),
    )
    // …then the app ships a 'tags' column between kind and os in the catalog.
    const headers = ref([
      { title: 'Actions', key: 'actions' },
      { title: 'Name', key: 'name' },
      { title: 'Tags', key: 'tags' },
      { title: 'Kind', key: 'kind' },
      { title: 'OS', key: 'os' },
    ])
    const g = useGridColumns({ headers, gridId: 'devices', scope: () => 'u1:t1' })
    const keys = g.effectiveHeaders.value.map((h: any) => h.key)
    expect(keys).toContain('tags')
    // Not dumped at the end: it lands before 'kind' (its catalog neighbour
    // relative to the saved order).
    expect(keys.indexOf('tags')).toBeLessThan(keys.indexOf('kind'))
  })

  it('survives corrupt storage', () => {
    localStorage.setItem('meshharbor:grid-cols:u1:t1:devices', '{not json')
    const g = fresh()
    expect(g.effectiveHeaders.value).toHaveLength(4)
  })
})
