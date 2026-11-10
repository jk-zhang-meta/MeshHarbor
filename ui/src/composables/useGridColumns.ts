// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { ref, computed, watch, type Ref, type ComputedRef } from 'vue'

/**
 * Generic per-user column preferences (visibility + order) for list grids.
 * Ported from lgr's ui-shared (same Vuetify-3 stack), with the identity
 * decoupled: meshharbor keeps no JWT in localStorage (cookie session), so the
 * caller supplies a `scope` — typically `${userId}:${tenantId}` — instead of
 * this file reading identity stores.
 *
 * The view keeps passing its full `headers` catalog; this composable projects
 * it through the user's saved preference:
 *   - hidden keys are dropped (the actions/expand columns are never hideable)
 *   - saved order wins; catalog keys not in the saved order (new columns
 *     shipped later) are spliced back at their catalog position, so a new
 *     column doesn't dump at the end for customized users
 *
 * Storage: `meshharbor:grid-cols:<scope>:<gridId>` → { order: string[], hidden: string[] }.
 */

export interface GridColumnEntry {
  key: string
  title: string
  visible: boolean
  locked: boolean
}

const NEVER_HIDE = new Set(['actions', 'data-table-expand', 'data-table-select'])

interface GridColsPref {
  order: string[]
  hidden: string[]
}

export function useGridColumns(opts: {
  headers: Ref<any[]> | ComputedRef<any[]>
  /** Stable grid identity — e.g. 'devices'. */
  gridId: string
  /** Per-user/per-org partition — e.g. `() => \`${userId}:${tenantId}\``. */
  scope: Ref<string> | ComputedRef<string> | (() => string)
}) {
  const scope = typeof opts.scope === 'function' ? computed(opts.scope) : opts.scope
  const storageKey = computed(
    () => `meshharbor:grid-cols:${scope.value || 'anon'}:${opts.gridId || 'grid'}`,
  )

  const pref = ref<GridColsPref>({ order: [], hidden: [] })

  function load() {
    try {
      const raw = localStorage.getItem(storageKey.value)
      const parsed = raw ? JSON.parse(raw) : null
      pref.value = {
        order: Array.isArray(parsed?.order)
          ? parsed.order.filter((k: any) => typeof k === 'string')
          : [],
        hidden: Array.isArray(parsed?.hidden)
          ? parsed.hidden.filter((k: any) => typeof k === 'string')
          : [],
      }
    } catch {
      pref.value = { order: [], hidden: [] }
    }
  }

  function save() {
    try {
      if (!pref.value.order.length && !pref.value.hidden.length)
        localStorage.removeItem(storageKey.value)
      else localStorage.setItem(storageKey.value, JSON.stringify(pref.value))
    } catch {
      /* quota / private browsing */
    }
  }

  watch(storageKey, load, { immediate: true })

  const keyed = computed(() =>
    (opts.headers.value || []).filter((h: any) => h && typeof h.key === 'string'),
  )

  /** Catalog keys in the user's order (saved first, new keys spliced in place). */
  const orderedKeys = computed<string[]>(() => {
    const catalog = keyed.value.map((h: any) => h.key)
    const saved = pref.value.order.filter((k) => catalog.includes(k))
    const rest = catalog.filter((k: string) => !saved.includes(k))
    const out = [...saved]
    for (const k of rest) {
      const catIdx = catalog.indexOf(k)
      let insertAt = out.length
      for (let i = 0; i < out.length; i++) {
        if (catalog.indexOf(out[i]) > catIdx) {
          insertAt = i
          break
        }
      }
      out.splice(insertAt, 0, k)
    }
    return out
  })

  const effectiveHeaders = computed(() => {
    const byKey = new Map(keyed.value.map((h: any) => [h.key, h]))
    const hidden = new Set(pref.value.hidden.filter((k) => !NEVER_HIDE.has(k)))
    const rows = orderedKeys.value
      .filter((k) => !hidden.has(k))
      .map((k) => byKey.get(k))
      .filter(Boolean)
    // Headers without a key (rare) keep their original trailing position.
    const unkeyed = (opts.headers.value || []).filter((h: any) => !h || typeof h.key !== 'string')
    return [...rows, ...unkeyed]
  })

  const entries = computed<GridColumnEntry[]>(() =>
    orderedKeys.value.map((k) => {
      const h: any = keyed.value.find((x: any) => x.key === k)
      return {
        key: k,
        title: String(h?.title ?? k),
        visible: !pref.value.hidden.includes(k),
        locked: NEVER_HIDE.has(k),
      }
    }),
  )

  function toggle(key: string) {
    if (NEVER_HIDE.has(key)) return
    const hidden = new Set(pref.value.hidden)
    if (hidden.has(key)) hidden.delete(key)
    else hidden.add(key)
    pref.value = { ...pref.value, hidden: [...hidden] }
    save()
  }

  function move(key: string, dir: -1 | 1) {
    const order = [...orderedKeys.value]
    const idx = order.indexOf(key)
    const to = idx + dir
    if (idx === -1 || to < 0 || to >= order.length) return
    order.splice(idx, 1)
    order.splice(to, 0, key)
    pref.value = { ...pref.value, order }
    save()
  }

  /** Drag & drop reorder — persist the full key order in one write. */
  function reorder(keys: string[]) {
    const known = new Set(orderedKeys.value)
    const order = keys.filter((k) => known.has(k))
    // Anything the drag payload missed (race with a catalog change) keeps its position.
    for (const k of orderedKeys.value) if (!order.includes(k)) order.push(k)
    pref.value = { ...pref.value, order }
    save()
  }

  function reset() {
    pref.value = { order: [], hidden: [] }
    save()
  }

  const customized = computed(() => pref.value.order.length > 0 || pref.value.hidden.length > 0)

  return { effectiveHeaders, entries, toggle, move, reorder, reset, customized }
}
