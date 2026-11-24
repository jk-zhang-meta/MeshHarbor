// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { shallowRef } from 'vue'

/**
 * FR-120 P4 — which rows of a phone list are open.
 *
 * On a phone a row shows what decides (a device's name, status and one
 * action; an audit entry's device, time and result) and the rest opens on a
 * tap, so a page stays within twice its desktop height (`docs/ui.md` §
 * Phones and tablets). Rows open independently, and each keeps its state
 * while the list re-renders around it. `toggle` replaces the set (a
 * `shallowRef`), so a template that reads `isOpen` re-renders.
 */
export function useOpenRows<K = string>(): {
  isOpen: (key: K) => boolean
  toggle: (key: K) => void
} {
  const open = shallowRef(new Set<K>())
  return {
    isOpen: (key: K) => open.value.has(key),
    toggle: (key: K) => {
      const next = new Set(open.value)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      open.value = next
    },
  }
}
